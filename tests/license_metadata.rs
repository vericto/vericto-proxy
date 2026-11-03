// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! Release-law metadata must change together instead of creating two licenses
//! for one version or an image whose labels disagree with its files.

use std::fs;

fn root(path: &str) -> String {
    fs::read_to_string(format!("{}/{}", env!("CARGO_MANIFEST_DIR"), path))
        .unwrap_or_else(|error| panic!("cannot read {path}: {error}"))
}

#[test]
fn version_5_is_the_first_agpl_release_everywhere() {
    let version = env!("CARGO_PKG_VERSION");
    let major: u64 = version.split('.').next().unwrap().parse().unwrap();
    assert!(
        major >= 5,
        "AGPL metadata must not be published as version 4.23.0"
    );

    let manifest = root("Cargo.toml");
    assert!(manifest.contains("license = \"AGPL-3.0-only\""));
    assert!(manifest.contains("tag = \"v5.0.0\""));

    let readme = root("README.md");
    assert!(readme.contains(&format!("vericto-proxy:{version}")));

    let history = root("LICENSE_HISTORY.md");
    assert!(history.contains("tag `v5.0.0`"));
    assert!(history.contains("68f72720ab1ed7abcada0a824c8e9bd9c922a3cb"));
    assert!(history.contains("52abdc7dd8a175c827c7b88ac7baa81a11a14a80"));
    assert!(history.contains("40e6f991eae8d0107ad2b943ab6bdcc9c58901b5"));
}

#[test]
fn public_license_is_the_unmodified_agpl() {
    let license = root("LICENSE");
    assert!(license.starts_with("                    GNU AFFERO GENERAL PUBLIC LICENSE\n"));
    assert!(license.contains("Version 3, 19 November 2007"));
    assert!(license.contains("Everyone is permitted to copy and distribute verbatim copies\n"));
    assert!(license.contains("of this license document, but changing it is not allowed."));
}

#[test]
fn cla_workflow_uses_the_permanent_v1_1_document_and_record() {
    let index = root("CLA.md");
    assert!(index.contains("[ICLA version 1.1](legal/cla/1.1.md)"));
    assert!(root("legal/cla/1.1.md").contains("Version 1.1"));
    assert!(root("legal/cla/1.0.md").contains("Version 1.0"));

    let workflow = root(".github/workflows/cla.yml");
    assert!(workflow.contains("const claPath = \"legal/cla/1.1.md\";"));
    assert!(workflow.contains("signatures/v1.1/cla.json"));
    assert!(workflow.contains("const exemptAccounts = new Set([\"vericto\", \"donkan168\"]);"));
    assert!(workflow.contains(
        "const allowedBots = new Set([\"vericto-bot[bot]\", \"dependabot[bot]\", \"github-actions[bot]\"]);"
    ));
    assert!(workflow.contains("} else if (!exemptAccounts.has(author.login)) {"));
    assert!(workflow.contains("context.payload.comment.body === signatureSentence"));
    assert!(!workflow.contains("contains(github.event.comment.body"));
    assert!(workflow.contains("github.paginate(github.rest.pulls.listCommits"));
    assert!(workflow.contains("github.paginate(github.rest.issues.listComments"));
    assert!(workflow.contains("Co-authored-by:"));
    assert!(workflow.contains("commit.commit.verification?.verified !== true"));
    assert!(workflow.contains("cla_document_sha256: claDocumentSha256"));
    assert!(workflow.contains("entry.cla_version === claVersion"));
    assert!(!workflow.contains("contributor-assistant/github-action"));
}

#[test]
fn image_and_dependency_notices_use_the_same_license() {
    let release = root(".github/workflows/release.yml");
    assert!(release.contains("org.opencontainers.image.licenses=AGPL-3.0-only"));
    assert!(
        release.contains(
            "org.opencontainers.image.source=https://github.com/${{ github.repository }}"
        )
    );
    assert!(release.contains("org.opencontainers.image.revision=${{ github.sha }}"));
    assert!(release.contains("name: release metadata gate"));

    let about = root("third-party/about.toml");
    assert!(about.contains("[vericto-proxy]\naccepted = [\"AGPL-3.0-only\"]"));
    assert!(about.contains("[vericto-engine]\naccepted = [\"AGPL-3.0-only\"]"));

    let notice = root("NOTICE");
    assert!(notice.contains("Version 5.0.0 of\n  the proxy pins version 5.0.0 of the engine"));
    assert!(notice.contains("RUNTIME_BASE_LICENSES"));
    assert!(
        root("third-party/runtime-base.txt")
            .contains("glibc-2.44, glibc-2.44-locale-posix and ld-linux-2.44")
    );
    assert!(root("Dockerfile").contains(
        "third-party/runtime-base.txt /usr/share/doc/vericto-proxy/RUNTIME_BASE_LICENSES"
    ));
    assert!(notice.contains("The contents of this NOTICE file are informational"));
}
