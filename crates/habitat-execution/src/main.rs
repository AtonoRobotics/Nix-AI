fn main() {
    println!("{}", serde_json::to_string(&habitat_execution::qemu_feature_declarations()).unwrap());
}
