use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn get(_attr: TokenStream, item: TokenStream) -> TokenStream {
    todo!("Implement later");
    item
}
