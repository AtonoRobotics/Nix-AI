fn main() {
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .type_attribute("habitat.agent.v1.CommandResult", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute("habitat.agent.v1.ErrorStatus", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(&["../../contracts/proto/habitat_agent_v1.proto"], &["../../contracts/proto"])
        .expect("compile canonical Agent ABI");
}
