fn main() {
    #[cfg(feature = "gui")]
    slint_build::compile("ui/app.slint").expect("failed to compile Slint UI");
}
