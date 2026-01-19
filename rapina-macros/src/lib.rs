use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, LitStr, parse_macro_input};

#[proc_macro_attribute]
pub fn get(attr: TokenStream, item: TokenStream) -> TokenStream {
    route_macro(attr, item)
}

#[proc_macro_attribute]
pub fn post(attr: TokenStream, item: TokenStream) -> TokenStream {
    route_macro(attr, item)
}

#[proc_macro_attribute]
pub fn put(attr: TokenStream, item: TokenStream) -> TokenStream {
    route_macro(attr, item)
}

#[proc_macro_attribute]
pub fn delete(attr: TokenStream, item: TokenStream) -> TokenStream {
    route_macro(attr, item)
}

fn route_macro(attr: TokenStream, item: TokenStream) -> TokenStream {
    let _path = parse_macro_input!(attr as LitStr);
    let func = parse_macro_input!(item as ItemFn);

    let func_name = &func.sig.ident;
    let func_block = &func.block;
    let func_output = &func.sig.output;
    let func_vis = &func.vis;

    let expanded = quote! {
        #func_vis async fn #func_name(
            _req: hyper::Request<hyper::body::Incoming>,
            _params: rapina::extract::PathParams,
        ) #func_output #func_block
    };

    TokenStream::from(expanded)
}
