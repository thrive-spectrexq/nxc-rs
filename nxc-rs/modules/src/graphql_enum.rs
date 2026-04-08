use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{http::HttpSession, NxcSession};
use serde_json::json;
use tracing::info;

pub struct GraphqlEnum {}

impl GraphqlEnum {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for GraphqlEnum {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for GraphqlEnum {
    fn name(&self) -> &'static str {
        "graphql_enum"
    }

    fn description(&self) -> &'static str {
        "Detects GraphQL endpoints and extracts schema via Introspection queries."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["http"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let http_sess = session
            .as_any_mut()
            .downcast_mut::<HttpSession>()
            .ok_or_else(|| anyhow!("Module requires an HTTP session"))?;

        let scheme = if http_sess.use_ssl { "https" } else { "http" };
        let base_url = format!("{}://{}:{}", scheme, http_sess.target, http_sess.port);

        info!(
            "Starting GraphQL Introspection enumeration against {}",
            base_url
        );

        let endpoints = vec![
            "/graphql",
            "/api/graphql",
            "/v1/graphql",
            "/v2/graphql",
            "/query",
        ];

        let introspection_query = r#"{"query":"\n    query IntrospectionQuery {\n      __schema {\n        queryType { name }\n        mutationType { name }\n        subscriptionType { name }\n        types {\n          ...FullType\n        }\n        directives {\n          name\n          description\n          locations\n          args {\n            ...InputValue\n          }\n        }\n      }\n    }\n\n    fragment FullType on __Type {\n      kind\n      name\n      description\n      fields(includeDeprecated: true) {\n        name\n        description\n        args {\n          ...InputValue\n        }\n        type {\n          ...TypeRef\n        }\n        isDeprecated\n        deprecationReason\n      }\n      inputFields {\n        ...InputValue\n      }\n      interfaces {\n        ...TypeRef\n      }\n      enumValues(includeDeprecated: true) {\n        name\n        description\n        isDeprecated\n        deprecationReason\n      }\n      possibleTypes {\n        ...TypeRef\n      }\n    }\n\n    fragment InputValue on __InputValue {\n      name\n      description\n      type { ...TypeRef }\n      defaultValue\n    }\n\n    fragment TypeRef on __Type {\n      kind\n      name\n      ofType {\n        kind\n        name\n        ofType {\n          kind\n          name\n          ofType {\n            kind\n            name\n            ofType {\n              kind\n              name\n              ofType {\n                kind\n                name\n                ofType {\n                  kind\n                  name\n                  ofType {\n                    kind\n                    name\n                  }\n                }\n              }\n            }\n          }\n        }\n      }\n    }\n  "}"#;

        let mut output = String::from("GraphQL Enumeration Results:\n");
        let mut found_schemas = Vec::new();

        for ep in endpoints {
            let url = format!("{}{}", base_url, ep);
            let mut req = http_sess
                .client
                .post(&url)
                .header("Content-Type", "application/json")
                .body(introspection_query.to_owned());

            if let Some(creds) = &http_sess.credentials {
                if let Some(pw) = &creds.password {
                    req = req.basic_auth(&creds.username, Some(pw));
                } else {
                    req = req.basic_auth(&creds.username, None::<&str>);
                }
            }

            if let Ok(res) = req.send().await {
                if res.status().is_success() {
                    if let Ok(body) = res.text().await {
                        if body.contains("__schema") && body.contains("queryType") {
                            output.push_str(&format!(
                                "  [+] Introspection extracted successfully at: {}\n",
                                url
                            ));
                            found_schemas.push(json!({
                                "endpoint": url,
                                "schema": body
                            }));
                            break; // Stop after finding the first valid one
                        }
                    }
                }
            }
        }

        if found_schemas.is_empty() {
            output.push_str(
                "  [!] No accessible GraphQL endpoints found or introspection is disabled.\n",
            );
        }

        Ok(ModuleResult {
            success: true,
            output,
            data: json!({ "graphql_schemas": found_schemas }),
            credentials: vec![],
        })
    }
}
