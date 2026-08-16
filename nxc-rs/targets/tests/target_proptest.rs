use nxc_targets::parse_targets;
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_parse_targets_never_panics_on_arbitrary_strings(s in "\\PC*") {
        // Must never panic on arbitrary Unicode or malformed input
        let _ = parse_targets(&s);
    }

    #[test]
    fn test_parse_targets_valid_ipv4(
        a in 0u8..=255,
        b in 0u8..=255,
        c in 0u8..=255,
        d in 0u8..=255,
    ) {
        let ip_str = format!("{a}.{b}.{c}.{d}");
        let res = parse_targets(&ip_str);
        prop_assert!(res.is_ok());
        let targets = res.unwrap();
        prop_assert_eq!(targets.len(), 1);
        prop_assert_eq!(targets[0].ip_string(), ip_str);
    }

    #[test]
    fn test_parse_targets_cidr_bounds(
        a in 1u8..=223,
        b in 0u8..=255,
        c in 0u8..=255,
        d in 0u8..=255,
        prefix in 24u32..=30,
    ) {
        let cidr_str = format!("{a}.{b}.{c}.{d}/{prefix}");
        let res = parse_targets(&cidr_str);
        prop_assert!(res.is_ok());
        let targets = res.unwrap();
        // Number of usable host IPs in a /prefix is 2^(32-prefix) - 2
        let expected_count = (1 << (32 - prefix)) - 2;
        prop_assert_eq!(targets.len(), expected_count);
    }
}
