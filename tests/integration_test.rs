use std::fs::{read, read_dir};

use test_case::test_case;

use btf_rs::*;

fn bytes() -> Btf {
    Btf::from_bytes(&read("tests/data/vmlinux").unwrap()).unwrap()
}

fn file() -> Btf {
    Btf::from_file("tests/data/vmlinux").unwrap()
}

fn split_file() -> Btf {
    let vmlinux = Btf::from_file("tests/data/vmlinux").unwrap();
    Btf::from_split_file("tests/data/openvswitch", &vmlinux).unwrap()
}

fn split_bytes() -> Btf {
    let vmlinux = Btf::from_bytes(&read("tests/data/vmlinux").unwrap()).unwrap();
    Btf::from_split_bytes(&read("tests/data/openvswitch").unwrap(), &vmlinux).unwrap()
}

#[test_case(bytes())]
#[test_case(file())]
#[test_case(split_file())]
#[test_case(split_bytes())]
fn resolve_ids_by_name(btf: Btf) {
    // Resolve primitive type.
    assert_eq!(btf.resolve_ids_by_name("int").unwrap().pop().unwrap(), 21);
    // Resolve typedef.
    assert_eq!(btf.resolve_ids_by_name("u64").unwrap().pop().unwrap(), 37);
    // Resolve struct.
    assert_eq!(
        btf.resolve_ids_by_name("sk_buff").unwrap().pop().unwrap(),
        3482
    );
    // Resolve function.
    assert_eq!(
        btf.resolve_ids_by_name("consume_skb")
            .unwrap()
            .pop()
            .unwrap(),
        36977
    );
}

#[test_case(bytes())]
#[test_case(file())]
#[test_case(split_file())]
#[test_case(split_bytes())]
fn resolve_types_by_name(btf: Btf) {
    let types = btf.resolve_types_by_name("consume_skb");
    assert!(types.is_ok());
    assert_eq!(types.unwrap().len(), 1);
}

#[test_case(bytes())]
#[test_case(file())]
#[test_case(split_file())]
#[test_case(split_bytes())]
fn resolve_types_by_name_unknown(btf: Btf) {
    assert!(btf.resolve_types_by_name("not_a_known_function").is_err());
}

#[test_case(bytes())]
#[test_case(file())]
#[test_case(split_file())]
#[test_case(split_bytes())]
fn check_resolved_type(btf: Btf) {
    let mut r#type = btf.resolve_types_by_name("sk_buff").unwrap();

    match r#type.pop().unwrap() {
        Type::Struct(_) => (),
        _ => panic!("Resolved type is not a struct"),
    }
}

#[test_case(bytes())]
#[test_case(file())]
#[test_case(split_file())]
#[test_case(split_bytes())]
fn bijection(btf: Btf) {
    let func = match btf.resolve_types_by_name("vmalloc").unwrap().pop().unwrap() {
        Type::Func(func) => func,
        _ => panic!("Resolved type is not a function"),
    };

    assert_eq!(btf.resolve_name(&func).unwrap(), "vmalloc");

    let func_id = btf.resolve_ids_by_name("vmalloc").unwrap().pop().unwrap();
    let func = match btf.resolve_type_by_id(func_id).unwrap() {
        Type::Func(func) => func,
        _ => panic!("Resolved type is not a function"),
    };

    assert_eq!(btf.resolve_name(&func).unwrap(), "vmalloc");
}

#[test_case(bytes())]
#[test_case(file())]
#[test_case(split_file())]
#[test_case(split_bytes())]
fn resolve_function(btf: Btf) {
    let func = match btf
        .resolve_types_by_name("kfree_skb_reason")
        .unwrap()
        .pop()
        .unwrap()
    {
        Type::Func(func) => func,
        _ => panic!("Resolved type is not a function"),
    };

    assert!(func.is_static());
    assert!(!func.is_global());
    assert!(!func.is_extern());

    let proto = match btf.resolve_chained_type(&func).unwrap() {
        Type::FuncProto(proto) => proto,
        _ => panic!("Resolved type is not a function proto"),
    };

    assert_eq!(proto.parameters.len(), 2);
    assert_eq!(btf.resolve_name(&proto.parameters[0]).unwrap(), "skb");
    assert!(!proto.parameters[0].is_variadic());
    assert_eq!(btf.resolve_name(&proto.parameters[1]).unwrap(), "reason");
    assert!(!proto.parameters[1].is_variadic());

    match btf.resolve_type_by_id(proto.return_type_id()).unwrap() {
        Type::Void => (),
        _ => panic!("Resolved type is not void"),
    }

    let ptr = match btf.resolve_chained_type(&proto.parameters[0]).unwrap() {
        Type::Ptr(ptr) => ptr,
        _ => panic!("Resolved type is not a pointer"),
    };

    match btf.resolve_chained_type(&proto.parameters[1]).unwrap() {
        Type::Enum(_) => (),
        _ => panic!("Resolved type is not an enum"),
    }

    let r#struct = match btf.resolve_chained_type(&ptr).unwrap() {
        Type::Struct(r#struct) => r#struct,
        _ => panic!("Resolved type is not a struct"),
    };

    assert_eq!(btf.resolve_name(&r#struct).unwrap(), "sk_buff");
    assert_eq!(r#struct.size(), 232);
    assert_eq!(r#struct.members.len(), 28);

    assert_eq!(btf.resolve_name(&r#struct.members[25]).unwrap(), "truesize");

    let arg = match btf.resolve_chained_type(&r#struct.members[25]).unwrap() {
        Type::Int(int) => int,
        _ => panic!("Resolved type is not an integer"),
    };

    assert_eq!(btf.resolve_name(&arg).unwrap(), "unsigned int");
    assert!(!arg.is_signed());
    assert!(!arg.is_char());
    assert!(!arg.is_bool());
}

#[test]
fn wrong_file() {
    assert!(Btf::from_file("/does/not/exist").is_err());
}

#[test_case(split_file())]
#[test_case(split_bytes())]
fn resolve_split_struct(btf: Btf) {
    let r#struct = btf
        .resolve_types_by_name("datapath")
        .unwrap()
        .pop()
        .unwrap();
    let expected = &[
        "rcu",
        "list_node",
        "table",
        "ports",
        "stats_percpu",
        "net",
        "user_features",
        "max_headroom",
        "meter_tbl",
        "upcall_portids",
    ];
    let r#struct = match r#struct {
        Type::Struct(r#struct) => r#struct,
        _ => panic!("Resolved type is not a struct"),
    };
    for (i, member) in r#struct.members.iter().enumerate() {
        let name = btf.resolve_name(member);
        assert!(name.is_ok());
        assert!(name.unwrap().eq(expected[i]));
    }

    let arg = match btf.resolve_chained_type(&r#struct.members[2]).unwrap() {
        Type::Struct(s) => s,
        _ => panic!("Resolved type is not an integer"),
    };
    assert_eq!(btf.resolve_name(&arg).unwrap(), "flow_table");
    assert_eq!(arg.members.len(), 7);
}

#[test_case(split_file())]
#[test_case(split_bytes())]
fn resolve_split_func(btf: Btf) {
    // Resolve the following function:
    // static int queue_userspace_packet(struct datapath *dp, struct sk_buff *skb,
    // 				  const struct sw_flow_key *key,
    // 				  const struct dp_upcall_info *upcall_info,
    // 				  uint32_t cutlen)

    let func = match btf
        .resolve_types_by_name("queue_userspace_packet")
        .unwrap()
        .pop()
        .unwrap()
    {
        Type::Func(func) => func,
        _ => panic!("Resolved type is not a function"),
    };

    assert!(func.is_static());
    assert!(!func.is_global());
    assert!(!func.is_extern());

    let proto = match btf.resolve_chained_type(&func).unwrap() {
        Type::FuncProto(proto) => proto,
        _ => panic!("Resolved type is not a function proto"),
    };

    assert_eq!(proto.parameters.len(), 5);
    assert_eq!(btf.resolve_name(&proto.parameters[0]).unwrap(), "dp");
    assert!(!proto.parameters[0].is_variadic());
    assert_eq!(btf.resolve_name(&proto.parameters[1]).unwrap(), "skb");
    assert!(!proto.parameters[1].is_variadic());

    match btf.resolve_type_by_id(proto.return_type_id()).unwrap() {
        Type::Int(_) => (),
        _ => panic!("Resolved type is not int"),
    }

    let ptr0 = match btf.resolve_chained_type(&proto.parameters[0]).unwrap() {
        Type::Ptr(ptr) => ptr,
        _ => panic!("Resolved type is not a pointer"),
    };

    let ptr1 = match btf.resolve_chained_type(&proto.parameters[1]).unwrap() {
        Type::Ptr(ptr) => ptr,
        _ => panic!("Resolved type is not a pointer"),
    };

    let struct0 = match btf.resolve_chained_type(&ptr0).unwrap() {
        Type::Struct(r#struct) => r#struct,
        _ => panic!("Resolved type is not a struct"),
    };

    let struct1 = match btf.resolve_chained_type(&ptr1).unwrap() {
        Type::Struct(r#struct) => r#struct,
        _ => panic!("Resolved type is not a struct"),
    };

    assert_eq!(btf.resolve_name(&struct0).unwrap(), "datapath");
    assert_eq!(struct0.size(), 136);
    assert_eq!(struct0.members.len(), 10);

    assert_eq!(btf.resolve_name(&struct1).unwrap(), "sk_buff");
    assert_eq!(struct1.size(), 232);
    assert_eq!(struct1.members.len(), 28);
}

#[test]
#[cfg_attr(not(feature = "test_runtime"), ignore)]
fn test_split_files() {
    let vmlinux = Btf::from_file("/sys/kernel/btf/vmlinux");
    if vmlinux.is_err() {
        return;
    }
    let vmlinux = vmlinux.unwrap();

    // Try parsing some the modules found in the system.
    if let Ok(dir) = read_dir("/sys/kernel/btf") {
        for f in dir
            .filter(|f| {
                f.is_ok()
                    && f.as_ref().unwrap().path().to_str().is_some()
                    && f.as_ref().unwrap().file_name().ne("vmlinux")
            })
            .take(10)
        {
            // Share the same base for all.
            assert!(Btf::from_split_file(f.as_ref().unwrap().path(), &vmlinux).is_ok());
        }
    }
}
