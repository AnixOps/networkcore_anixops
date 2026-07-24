use engine_singbox::{
    inspect_sing_box_local_selector_snapshot, read_sing_box_clash_api_selector,
    rewrite_sing_box_local_selector_default, select_sing_box_clash_api_outbound,
    sing_box_config_sha256, SingBoxClashApiSelectorStatus,
};
use platform_windows::managed::{
    read_managed_config, windows_managed_config_path, write_managed_text_atomic,
};
use std::fs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedNodeSwitch {
    pub node_id: String,
    pub config_sha256: String,
}

pub fn switch_generated_node(
    node_id: String,
    outbound_tag: String,
    expected_config_sha256: String,
) -> Result<PersistedNodeSwitch, String> {
    let managed_path = windows_managed_config_path();
    let managed = read_managed_config(&managed_path).map_err(|error| error.to_string())?;
    let sing_box = managed
        .sing_box
        .filter(|sing_box| sing_box.enabled)
        .ok_or_else(|| "Import a generated sing-box profile before switching nodes".to_string())?;
    let content = fs::read_to_string(&sing_box.config_path).map_err(|error| {
        format!(
            "managed sing-box configuration could not be read from {}: {error}",
            sing_box.config_path.display()
        )
    })?;
    if sing_box_config_sha256(&content) != expected_config_sha256 {
        return Err(
            "Managed generated profile changed. Reload or import the current profile before switching nodes."
                .to_string(),
        );
    }
    let selector = inspect_sing_box_local_selector_snapshot(&content).ok_or_else(|| {
        "Managed sing-box configuration does not contain the generated local selector".to_string()
    })?;
    if !selector
        .outbound_tags
        .iter()
        .any(|candidate| candidate == &outbound_tag)
    {
        return Err("Selected node is not part of the active generated profile".to_string());
    }

    let observed = read_sing_box_clash_api_selector(&selector.controller)
        .map_err(|error| error.to_string())?;
    if !selector_status_matches_generated_profile(&observed, &selector.outbound_tags) {
        return Err(
            "sing-box selector did not report the active generated profile; refresh or reconnect before switching nodes."
                .to_string(),
        );
    }
    let previous_outbound_tag = observed.current_outbound_tag;
    if previous_outbound_tag != outbound_tag {
        select_sing_box_clash_api_outbound(&selector.controller, &outbound_tag)
            .map_err(|error| error.to_string())?;
    }

    let rewritten = rewrite_sing_box_local_selector_default(&content, &outbound_tag)
        .map_err(|error| error.to_string())?;
    let current_content = fs::read_to_string(&sing_box.config_path).map_err(|error| {
        restore_active_outbound(
            &selector.controller,
            &previous_outbound_tag,
            &format!(
                "managed sing-box configuration could not be reread from {}: {error}",
                sing_box.config_path.display()
            ),
        )
    })?;
    if current_content != content {
        return Err(restore_active_outbound(
            &selector.controller,
            &previous_outbound_tag,
            "managed sing-box configuration changed while the node switch was in progress",
        ));
    }
    if let Err(error) = write_managed_text_atomic(&sing_box.config_path, &rewritten) {
        return Err(restore_active_outbound(
            &selector.controller,
            &previous_outbound_tag,
            &format!("selected node could not be persisted for the next service start: {error}"),
        ));
    }

    Ok(PersistedNodeSwitch {
        node_id,
        config_sha256: sing_box_config_sha256(&rewritten),
    })
}

fn restore_active_outbound(
    controller: &engine_singbox::SingBoxLocalControllerConfig,
    previous_outbound_tag: &str,
    reason: &str,
) -> String {
    match select_sing_box_clash_api_outbound(controller, previous_outbound_tag) {
        Ok(status) if status.current_outbound_tag == previous_outbound_tag => reason.to_string(),
        Ok(status) => format!(
            "{reason}; sing-box selector rollback did not restore {} (current {})",
            previous_outbound_tag, status.current_outbound_tag
        ),
        Err(error) => format!(
            "{reason}; sing-box selector rollback to {} failed: {error}",
            previous_outbound_tag
        ),
    }
}

fn selector_status_matches_generated_profile(
    status: &SingBoxClashApiSelectorStatus,
    generated_outbounds: &[String],
) -> bool {
    status.outbound_tags.len() == generated_outbounds.len()
        && generated_outbounds.iter().all(|expected| {
            status
                .outbound_tags
                .iter()
                .any(|observed| observed == expected)
        })
        && generated_outbounds
            .iter()
            .any(|candidate| candidate == &status.current_outbound_tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_status_must_match_the_generated_catalog_before_switching() {
        let tags = vec![
            "networkcore-node-0".to_string(),
            "networkcore-node-1".to_string(),
        ];
        let status = SingBoxClashApiSelectorStatus {
            selector_tag: "networkcore-selector".to_string(),
            current_outbound_tag: "networkcore-node-1".to_string(),
            outbound_tags: tags.clone(),
        };
        assert!(selector_status_matches_generated_profile(&status, &tags));

        let reordered = SingBoxClashApiSelectorStatus {
            outbound_tags: vec![
                "networkcore-node-1".to_string(),
                "networkcore-node-0".to_string(),
            ],
            ..status.clone()
        };
        assert!(selector_status_matches_generated_profile(&reordered, &tags));

        let missing = SingBoxClashApiSelectorStatus {
            outbound_tags: vec!["networkcore-node-0".to_string()],
            ..status
        };
        assert!(!selector_status_matches_generated_profile(&missing, &tags));
    }
}
