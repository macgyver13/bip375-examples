fn main() {
    uniffi::generate_scaffolding("src/spdk_psbt.udl").unwrap();
}
