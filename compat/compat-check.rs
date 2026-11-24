// Scratch: the real vault client against a vault-server (not committed).
use std::time::Duration;
use vault_cloud::*;
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (server, fp, admin) = (&a[1], &a[2], &a[3]);
    let ca = OwnCa::fetch(server, fp).expect("fetch ca");
    let s = Server::with_ca(server, Some(ca.pem())).unwrap();
    println!("info: {:?}", s.info().unwrap());
    let mb = random_mailbox().unwrap();
    let tok = random_token().unwrap();
    let dev = s.create(&mb, admin, &tok, "Alex laptop").unwrap();
    println!("created device {dev}");
    let m = Mailbox::new(server, &mb, &tok, Some(ca.pem())).unwrap();
    assert!(matches!(m.get(None).unwrap(), Fetched::Empty(0)));
    assert_eq!(m.put(0, b"sealed vault bytes").unwrap(), Saved::Saved(1));
    assert_eq!(m.put(0, b"late").unwrap(), Saved::Conflict(1));
    let t = m.ticket().unwrap();
    let link = JoinLink { server: server.clone(), mailbox: mb.clone(), ticket: t.ticket, fingerprint: Some(fp.clone()), shared: false };
    let parsed = JoinLink::parse(&link.to_link()).unwrap();
    let ca2 = OwnCa::fetch(&parsed.server, parsed.fingerprint.as_deref().unwrap()).unwrap();
    let s2 = Server::with_ca(&parsed.server, Some(ca2.pem())).unwrap();
    let tok2 = random_token().unwrap();
    let dev2 = s2.join(&parsed, &tok2, "Alex phone").unwrap();
    let m2 = Mailbox::new(server, &mb, &tok2, Some(ca2.pem())).unwrap();
    match m2.get(None).unwrap() { Fetched::File(1, b) => assert_eq!(b, b"sealed vault bytes"), _ => panic!() }
    let mut ws = m2.watch(Duration::from_secs(5)).unwrap();
    println!("watch hello: {}", ws.read().unwrap());
    m.put(1, b"v2").unwrap();
    println!("watch after save: {}", ws.read().unwrap());
    println!("devices: {}", m.devices().unwrap().len());
    m.remove_device(&dev2).unwrap();
    println!("after remove: {:?}", ws.read().map(|x| x.to_string()));
    assert!(m2.get(None).is_err());
    m.delete().unwrap();
    println!("ALL OK");
}
