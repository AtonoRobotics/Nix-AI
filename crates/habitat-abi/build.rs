fn main() {
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .type_attribute("nix_ai.agent.v2.CommandResult", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute("nix_ai.agent.v2.ErrorStatus", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(&["../../contracts/proto/nix_ai_agent_v2.proto"], &["../../contracts/proto"])
        .expect("compile canonical Agent ABI");
}
