use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::*;

#[proc_macro_attribute]
pub fn cbtf_type(_: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as Item);

    quote! {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, btf_rs_derive::CBtfType)]
        #[repr(C, packed)]
        #input
    }
    .into()
}

#[proc_macro_derive(CBtfType)]
pub fn cbtf_type_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let name = &ast.ident;

    let fields = match ast.data {
        Data::Struct(data) => match data.fields {
            Fields::Named(fields) => fields.named,
            _ => panic!("{name} is not a struct with named fields"),
        },
        _ => panic!("{name} is not a struct"),
    };

    let mut offset = 0;
    let bytes_fields = fields
        .iter()
        .map(|f| gen_bytes_field(f.ident.as_ref().unwrap(), &f.ty, &mut offset));
    let reader_fields = fields
        .iter()
        .map(|f| gen_reader_field(f.ident.as_ref().unwrap(), &f.ty));

    quote! {
        impl #name {
            pub(super) fn from_bytes(
                buf: &[u8],
                endianness: &Endianness
            ) -> crate::Result<Self> {
                Ok(#name {
                    #( #bytes_fields )*
                })
            }

            pub(super) fn from_reader<R: std::io::Read>(
                reader: &mut R,
                endianness: &crate::cbtf::Endianness,
            ) -> crate::Result<Self> {
                Ok(#name {
                    #( #reader_fields )*
                })
            }
        }
    }
    .into()
}

// Generate struct fields initialization using the input data from bytes.
// e.g. `u32 val: endianness.u32_from_bytes(&buf[0..4])?,`
fn gen_bytes_field(ident: &Ident, r#type: &Type, offset: &mut usize) -> proc_macro2::TokenStream {
    let ty = match r#type {
        Type::Path(tp) => &tp.path,
        _ => panic!("Field {ident:?} is not a plain type"),
    };

    let from = *offset;
    match ty.to_token_stream().to_string().as_str() {
        "u16" => {
            *offset += 2;
            quote! {
                #ident: endianness.u16_from_bytes(&buf[#from..])?,
            }
        }
        "u32" => {
            *offset += 4;
            quote! {
                #ident: endianness.u32_from_bytes(&buf[#from..])?,
            }
        }
        "i32" => {
            *offset += 4;
            quote! {
                #ident: endianness.i32_from_bytes(&buf[#from..])?,
            }
        }
        ty => panic!("Unsupported field type ({ty})"),
    }
}

// Generate struct fields initialization using the input data from a reader.
// e.g. `u32 val: endianness.u32_from_reader(reader)?,`
fn gen_reader_field(ident: &Ident, r#type: &Type) -> proc_macro2::TokenStream {
    let ty = match r#type {
        Type::Path(tp) => &tp.path,
        _ => panic!("Field {ident:?} is not a plain type"),
    };

    match ty.to_token_stream().to_string().as_str() {
        "u16" => quote! {
            #ident: endianness.u16_from_reader(reader)?,
        },
        "u32" => quote! {
            #ident: endianness.u32_from_reader(reader)?,
        },
        "i32" => quote! {
            #ident: endianness.i32_from_reader(reader)?,
        },
        ty => panic!("Unsupported field type ({ty})"),
    }
}
