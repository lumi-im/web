extern crate axolotl;
extern crate crossbeam;
extern crate handlebars_iron;
extern crate hyper;
extern crate iron;
extern crate mime;
extern crate mount;
extern crate redis;
extern crate router;
extern crate rustc_serialize;
extern crate serde;
extern crate serde_json;
extern crate sodiumoxide;
extern crate staticfile;
extern crate time;
extern crate toml;
extern crate url;
extern crate uuid;

use std::borrow::Cow;
use std::collections::{BTreeMap};
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;
use std::thread::sleep;
use std::thread;
use std::time::Duration;

use axolotl::derived::{Mac};
use axolotl::keys::{IdentityKey, IdentityKeyPair, KeyPair, SecretKey, PreKeyBundle, PreKey, PreKeyId, PublicKey};
use axolotl::message::{Message, Envelope, CipherMessage, PreKeyMessage, Counter, SessionTag};
use axolotl::session::{PreKeyStore, Session};

use handlebars_iron::{Template, HandlebarsEngine};
use hyper::Client;
use hyper::header::{Headers, ContentType, Accept, Quality, QualityItem};
use iron::middleware::Chain;
use iron::modifiers::Redirect;
use iron::prelude::Set;
use iron::{Url, Iron, Request, Response, IronResult, status};
use mime::{Mime, TopLevel, SubLevel};
use mount::Mount;
use redis::{Commands, RedisResult};
use router::{Router};
use rustc_serialize::hex::{FromHex, ToHex};
use rustc_serialize::json::{ToJson, Json, DecoderError};
use rustc_serialize::json;
use sodiumoxide::crypto::auth::hmacsha256::Tag;
use staticfile::Static;
use toml::Table;
use uuid::Uuid;

const SERVER_URL: &'static str = "http://127.0.0.1:5000/";

struct LumiPreKeyStore {
    pub prekeys: Vec<PreKey>
}

impl ToJson for LumiPreKeyStore {
    fn to_json(&self) -> Json {
        let mut prekeys = Vec::new();
        for prekey in &self.prekeys {
            let mut pk = BTreeMap::new();
            pk.insert("id".to_string(), prekey.key_id.value().to_json());
            pk.insert("public".to_string(), prekey.key_pair.public_key.fingerprint().to_json());
            pk.insert("secret".to_string(), prekey.key_pair.secret_key.0.to_hex().to_json());
            prekeys.push(pk);
        }
        prekeys.to_json()
    }
}

impl LumiPreKeyStore {
    pub fn new(prekeys: Vec<PreKey>) -> LumiPreKeyStore {
        LumiPreKeyStore {
            prekeys: prekeys
        }
    }
    pub fn load_from_config(config: &Table) -> LumiPreKeyStore {
        let spks = config.get("prekeys").unwrap().as_slice().unwrap();
        let mut prekeys = Vec::new();
        for spk in spks {
            let id = PreKeyId::new(spk.lookup("id").unwrap().as_integer().unwrap() as u16);
            let key = spk.lookup("key").unwrap().as_str().unwrap().from_hex().unwrap();
            let mut sk = [0u8; 32];
            for i in 0..32 {
                sk[i] = key[i];
            };
            let secret_key = SecretKey(sk);
            let public_key = PublicKey::from_secretkey(&secret_key);
            let key_pair = KeyPair {
                secret_key: secret_key,
                public_key: public_key
            };
            let pk = PreKey {
                key_id: id,
                key_pair: key_pair
            };
            prekeys.push(pk);
        }
        LumiPreKeyStore::new(prekeys)
    }
}

impl PreKeyStore for LumiPreKeyStore {
    type Error = ();

    fn get(&mut self, id: PreKeyId) -> Result<Option<PreKey>, ()> {
        Ok(self.prekeys.iter().find(|k| k.key_id == id).map(|k| k.clone()))
    }

    fn remove(&mut self, id: PreKeyId) -> Result<(), ()> {
        self.prekeys.iter()
            .position(|k| k.key_id == id)
            .map(|ix| self.prekeys.swap_remove(ix));
        Ok(())
    }
}

fn get_config() -> Option<Table> {
    let path = "/Users/limeburst/.lumi/config-".to_string() + &get_instance_port().to_string();
    let mut f = File::open(path).unwrap();
    let mut s = String::new();
    let _ = f.read_to_string(&mut s);
    let mut parser = toml::Parser::new(&s);
    parser.parse()
}

fn get_identity_keypair(config: &Table) -> IdentityKeyPair {
    let identity = config.get("identity").unwrap();
    let key = identity.lookup("key").unwrap().as_str().unwrap().from_hex().unwrap();
    let mut sk = [0u8; 32];
    for i in 0..32 {
        sk[i] = key[i];
    };
    let secret_key = SecretKey(sk);
    let public_key = PublicKey::from_secretkey(&secret_key);
    let keypair = KeyPair {
        secret_key: secret_key,
        public_key: public_key
    };
    IdentityKeyPair::from_keypair(keypair)
}

fn register_identity(ident: &IdentityKey) {
    let client = Client::new();
    let res = client.post("http://127.0.0.1:5000/identities/")
        .body(&ident.fingerprint())
        .send()
        .unwrap();
    assert_eq!(res.status, hyper::Ok);
}

fn register_prekeys(ident: &IdentityKey, store: &LumiPreKeyStore) {
    let mimetype_json = Mime(TopLevel::Application, SubLevel::Json, vec![]);
    let json_quality = QualityItem::new(mimetype_json.clone(), Quality(1));
    let mut headers = Headers::new();
    headers.set(Accept(vec![json_quality]));
    headers.set(ContentType(mimetype_json.clone()));
    let mut map = BTreeMap::new();
    for prekey in &store.prekeys {
        map.insert(prekey.key_id.0.to_string(), prekey.key_pair.public_key.fingerprint());
    }
    let client = Client::new();
    let url = [SERVER_URL, &*ident.public_key.fingerprint(), "/prekeys/"].join("");
    let res = client.post(&url)
        .headers(headers.clone())
        .body(&serde_json::to_string(&map).unwrap())
        .send()
        .unwrap();
    assert_eq!(res.status, hyper::Ok);
}

fn request_prekey(identity_key: IdentityKey) -> PreKeyBundle {
    let client = Client::new();
    let url = [
        "http://127.0.0.1:5000/",
        &*identity_key.public_key.fingerprint(),
        "/prekeys/random/"
            ].join("");
    let mut res = client.get(&url)
        .send()
        .unwrap();
    assert_eq!(res.status, hyper::Ok);
    let mut body = String::new();
    res.read_to_string(&mut body).unwrap();
    let prekey: BTreeMap<String, String> = json::decode(&body).unwrap();
    let bytebuffer = prekey.get("key").unwrap().from_hex().unwrap();
    let mut buffer = [0u8; 32];
    for i in 0..32 {
        buffer[i] = bytebuffer[i]
    };
    PreKeyBundle {
        prekey_id: PreKeyId(u16::from_str(prekey.get("id").unwrap()).unwrap()),
        public_key: PublicKey(buffer),
        identity_key: identity_key,
        signature: None,
    }
}

#[derive(RustcDecodable, RustcEncodable)]
struct LumiMessageSendRequest {
    pub to: String,
    pub message: LumiMessage,
}

impl ToJson for LumiMessageSendRequest {
    fn to_json(&self) -> Json {
        let mut req = BTreeMap::new();
        req.insert("to".to_string(), self.to.clone().to_json());
        req.insert("message".to_string(), self.message.to_json());
        req.to_json()
    }
}

#[derive(RustcDecodable, RustcEncodable)]
struct LumiMessageStored {
    pub text: String,
    pub group_id: Option<Uuid>,
    pub identity: String,
}

impl ToJson for LumiMessageStored {
    fn to_json(&self) -> Json {
        let mut sm = BTreeMap::new();
        sm.insert("text".to_string(), self.text.clone());
        sm.insert("identity".to_string(), self.identity.clone());
        match self.group_id {
            Some(g) => {
                sm.insert("group_id".to_string(), g.to_hyphenated_string());
            },
            None => ()
        }
        sm.to_json()
    }
}

#[derive(RustcDecodable, RustcEncodable, Clone)]
struct LumiMessage {
    pub text: String,
    pub group_id: Option<Uuid>,
}

impl ToJson for LumiMessage {
    fn to_json(&self) -> Json {
        let mut msg = BTreeMap::new();
        msg.insert("text".to_string(), self.text.clone());
        match self.group_id {
            Some(g) => {
                msg.insert("group_id".to_string(), g.to_hyphenated_string());
            },
            None => ()
        }
        msg.to_json()
    }
}

#[derive(RustcDecodable, RustcEncodable)]
struct LumiGroup {
    pub id: Uuid,
    pub name: String,
    pub members: Vec<String>,
}

impl ToJson for LumiGroup {
    fn to_json(&self) -> Json {
        let mut group = BTreeMap::new();
        group.insert("id".to_string(), self.id.to_hyphenated_string().to_json());
        group.insert("name".to_string(), self.name.to_json());
        group.insert("members".to_string(), self.members.to_json());
        group.to_json()
    }
}

fn main() {
    let mut mount = Mount::new();
    mount.mount("/static/", Static::new(Path::new("./src/static/")));
    let mut router = Router::new();
    router.get("/", root_handler);
    router.get("/prekeys/", prekeys_handler);
    router.get("/identities/", identities_handler);
    router.get("/identities/:query/", private_chat_get_handler);
    router.get("/identities/:query/messages/", private_chat_messages_get_handler);
    router.post("/identities/:query/", private_chat_post_handler);
    router.get("/groups/", groups_get_handler);
    router.post("/groups/", groups_post_handler);
    router.get("/groups/:query/", group_get_handler);
    router.get("/groups/:query/messages/", group_messages_get_handler);
    router.post("/groups/:query/", group_post_handler);
    router.post("/groups/:query/leave/", leave_group);
    router.post("/groups/:query/invite/", invite_group);
    let mut chain = Chain::new(router);
    chain.link_after(HandlebarsEngine::new("./src/templates/", ".hbs"));
    mount.mount("/", chain);

    fn prekeys_handler(_: &mut Request) -> IronResult<Response> {
        let mut resp = Response::new();
        let config = get_config().unwrap();
        let store = LumiPreKeyStore::load_from_config(&config);
        resp.set_mut(Template::new("prekeys", store.to_json())).set_mut(status::Ok);
        Ok(resp)
    }

    fn root_handler(_: &mut Request) -> IronResult<Response> {
        let base = [
            "http://127.0.0.1:",
            get_instance_port().to_string().as_ref(),
            "/identities/"].join("");
        let url = Url::parse(&base).unwrap();
        Ok(Response::with((status::Found, Redirect(url))))

    }

    fn leave_group(req: &mut Request) -> IronResult<Response> {
        let ref query = req.extensions.get::<Router>()
            .unwrap().find("query").unwrap_or("/");
        let group_id = Uuid::parse_str(query).unwrap();
        let group = get_group(&group_id).unwrap();
        notify_group_leaving(&group);
        delete_group(&group);
        delete_group_messages(&group);
        let base = [
            "http://127.0.0.1:",
            get_instance_port().to_string().as_ref(),
            "/groups/"].join("");
        let url = Url::parse(&base).unwrap();
        Ok(Response::with((status::Found, Redirect(url))))
    }

    fn group_get_handler(req: &mut Request) -> IronResult<Response> {
        let mut resp = Response::new();
        let ref query = req.extensions.get::<Router>()
            .unwrap().find("query").unwrap_or("/");
        let group_id = Uuid::parse_str(query).unwrap();
        let group = get_group(&group_id).unwrap();
        let mut data = BTreeMap::new();
        let config = get_config().unwrap();
        let ikp = get_identity_keypair(&config);
        let messages = get_stored_messages(&(ikp.public_key.fingerprint() + query));
        let mut identities = get_identities();
        identities.retain(|x| !group.members.contains(x));
        data.insert("identities".to_string(), identities.to_json());
        data.insert("messages".to_string(), messages.to_json());
        data.insert("group".to_string(), group.to_json());
        resp.set_mut(Template::new("group", data)).set_mut(status::Ok);
        Ok(resp)
    }

    fn group_messages_get_handler(req: &mut Request) -> IronResult<Response> {
        let ref query = req.extensions.get::<Router>()
            .unwrap().find("query").unwrap_or("/");
        let config = get_config().unwrap();
        let ikp = get_identity_keypair(&config);
        let messages = get_stored_messages(&(ikp.public_key.fingerprint() + query));
        Ok(Response::with((status::Ok, json::encode(&messages).unwrap())))
    }

    fn group_post_handler(req: &mut Request) -> IronResult<Response> {
        let ref query = req.extensions.get::<Router>()
            .unwrap().find("query").unwrap_or("/");
        let mut payload = String::new();
        let _ = req.body.read_to_string(&mut payload);
        let test = url::form_urlencoded::parse(payload.as_bytes());
        let mut text = String::new();
        let group_id = Uuid::parse_str(query).unwrap();
        let group = get_group(&group_id).unwrap();
        for (key, value) in test {
            if key == "text" {
                text = value
            }
        };
        let msg = LumiMessage {
            text: text,
            group_id: Some(group_id),
        };
        for member in group.members {
            let req = LumiMessageSendRequest {
                to: member,
                message: msg.clone()
            };
            queue_message(&req);
        }
        let base = [
            "http://127.0.0.1:",
            get_instance_port().to_string().as_ref(),
            "/groups/",
            *query
            ].join("");
        let url = Url::parse(&base).unwrap();
        Ok(Response::with((status::Found, Redirect(url))))
    }

    fn invite_group(req: &mut Request) -> IronResult<Response> {
        let ref query = req.extensions.get::<Router>()
            .unwrap().find("query").unwrap_or("/");
        let mut payload = String::new();
        let group_id = Uuid::parse_str(query).unwrap();
        let mut group = get_group(&group_id).unwrap();
        delete_group(&group);
        let _ = req.body.read_to_string(&mut payload);
        let test = url::form_urlencoded::parse(payload.as_bytes());
        let mut members = Vec::new();
        for (key, value) in test {
            if key == "members" {
                members.push(value);
            }
        };
        group.members.append(&mut members);
        save_group(&group);
        notify_group_update(&group);
        let base = [
            "http://127.0.0.1:",
            get_instance_port().to_string().as_ref(),
            "/groups/",
            *query
            ].join("");
        let url = Url::parse(&base).unwrap();
        Ok(Response::with((status::Found, Redirect(url))))
    }

    fn groups_get_handler(_: &mut Request) -> IronResult<Response> {
        let mut resp = Response::new();
        let identities = get_others_identities();
        let mut data = BTreeMap::new();
        let config = get_config().unwrap();
        let ikp = get_identity_keypair(&config);
        let groups = get_groups();
        data.insert("groups".to_string(), groups.to_json());
        data.insert("identity".to_string(), ikp.public_key.fingerprint().to_json());
        data.insert("identities".to_string(), identities.to_json());
        resp.set_mut(Template::new("groups", data)).set_mut(status::Ok);
        Ok(resp)
    }

    fn groups_post_handler(req: &mut Request) -> IronResult<Response> {
        let mut payload = String::new();
        let _ = req.body.read_to_string(&mut payload);
        let test = url::form_urlencoded::parse(payload.as_bytes());
        let mut members = Vec::new();
        let mut name = String::new();
        for (key, value) in test {
            if key == "members" {
                members.push(value);
            } else if key == "name" {
                name = value
            }
        };
        let mut base = [
            "http://127.0.0.1:",
            get_instance_port().to_string().as_ref(),
            "/groups/"].join("");
        if members.len() > 0 && name != "" {
            let config = get_config().unwrap();
            let ikp = get_identity_keypair(&config);
            members.push(ikp.public_key.fingerprint());
            let group = LumiGroup {
                members: members,
                name: name,
                id: Uuid::new_v4(),
            };
            save_group(&group);
            notify_group_update(&group);
            base = [base, group.id.to_hyphenated_string()].join("");
        };
        let url = Url::parse(&base).unwrap();
        Ok(Response::with((status::Found, Redirect(url))))
    }

    fn identities_handler(_: &mut Request) -> IronResult<Response> {
        let mut resp = Response::new();
        let config = get_config().unwrap();
        let ikp = get_identity_keypair(&config);
        let identities = get_others_identities();
        let mut data = BTreeMap::new();
        data.insert("identity".to_string(), ikp.public_key.fingerprint().to_json());
        data.insert("identities".to_string(), identities.to_json());
        resp.set_mut(Template::new("identities", data)).set_mut(status::Ok);
        Ok(resp)
    }

    fn private_chat_get_handler(req: &mut Request) -> IronResult<Response> {
        let ref query = req.extensions.get::<Router>()
            .unwrap().find("query").unwrap_or("/");
        let mut resp = Response::new();
        let mut data = BTreeMap::new();
        let config = get_config().unwrap();
        let ikp = get_identity_keypair(&config);
        let id = ikp.public_key.fingerprint() + query;
        let msgs = get_stored_messages(&id);
        let mut messages = Vec::new();
        for msg in msgs {
            match msg.group_id {
                None => {
                    messages.push(msg);
                },
                _ => {}
            }
        }
        data.insert("identity".to_string(), query.to_json());
        data.insert("messages".to_string(), messages.to_json());
        resp.set_mut(Template::new("private_chat", data)).set_mut(status::Ok);
        Ok(resp)
    }

    fn private_chat_messages_get_handler(req: &mut Request) -> IronResult<Response> {
        let ref query = req.extensions.get::<Router>()
            .unwrap().find("query").unwrap_or("/");
        let config = get_config().unwrap();
        let ikp = get_identity_keypair(&config);
        let id = ikp.public_key.fingerprint() + query;
        let msgs = get_stored_messages(&id);
        let mut messages = Vec::new();
        for msg in msgs {
            match msg.group_id {
                None => {
                    messages.push(msg);
                },
                _ => {}
            }
        }
        Ok(Response::with((status::Ok, json::encode(&messages).unwrap())))
    }

    fn private_chat_post_handler(req: &mut Request) -> IronResult<Response> {
        let query = req.extensions.get::<Router>()
            .unwrap().find("query").unwrap_or("/");
        let mut payload = String::new();
        let _ = req.body.read_to_string(&mut payload);
        let test = url::form_urlencoded::parse(payload.as_bytes());
        let mut text = String::new();
        for (key, value) in test {
            if key == "text" {
                text = value
            }
        };
        let msg = LumiMessage {
            text: text,
            group_id: None,
        };
        let req = LumiMessageSendRequest {
            to: query.to_string(),
            message: msg
        };
        queue_message(&req);
        let base = [
            "http://127.0.0.1:",
            get_instance_port().to_string().as_ref(),
            "/identities/"].join("");
        let url = Url::parse(&(base + query)).unwrap();
        Ok(Response::with((status::Found, Redirect(url))))
    }

    let config = get_config().unwrap();
    let ikp = get_identity_keypair(&config);
    let store = LumiPreKeyStore::load_from_config(&config);
    register_identity(&ikp.public_key);
    register_prekeys(&ikp.public_key, &store);

    thread::spawn(|| {
        let config = get_config().unwrap();
        let ikp = get_identity_keypair(&config);
        let mut sessions = BTreeMap::<String, Session>::new();
        let mut store = LumiPreKeyStore::load_from_config(&config);
        let duration = Duration::from_millis(100);
        loop {
            sleep(duration);
            let send_queue_id = ikp.public_key.fingerprint() + "-send-queue";
            let client = redis::Client::open("redis://127.0.0.1/").unwrap();
            let con = client.get_connection().unwrap();
            let m: RedisResult<String> = con.lpop(send_queue_id);
            match m {
                Ok(m) => {
                    let req: LumiMessageSendRequest = json::decode(&m).unwrap();
                    let msg = req.message;
                    let id = ikp.public_key.fingerprint() + &req.to;
                    if sessions.contains_key(&req.to) {
                        let session = sessions.get_mut(&req.to).unwrap();
                        send_message(&json::encode(&msg).unwrap(), session);
                    } else {
                        let mut buffer = [0u8; 32];
                        for i in 0..32 {
                            buffer[i] = req.to.from_hex().unwrap()[i];
                        };
                        let to_identity_key = IdentityKey::new(PublicKey(buffer));
                        let bundle = request_prekey(to_identity_key);
                        let mut session = Session::init_from_prekey(&ikp, bundle);
                        send_message(&json::encode(&msg).unwrap(), &mut session);
                        sessions.insert(req.to.clone(), session);
                    };
                    let sm = LumiMessageStored {
                        text: msg.text,
                        group_id: msg.group_id,
                        identity: ikp.public_key.fingerprint(),
                    };
                    store_message(&sm, &id);
                },
                Err(_) => {}
            }
            let envelope = get_oldest_message(&ikp);
            match envelope {
                Some(e) => {
                    let session_tag;
                    match e.message {
                        Message::Plain(ref m) => {
                            let tag = &*m.session_tag.tag.clone();
                            session_tag = tag.to_hex();
                        },
                        Message::Keyed(ref m) => {
                            let tag = &*m.message.session_tag.tag.clone();
                            session_tag = tag.to_hex();
                        },
                    };
                    let plaintext;
                    let identity;
                    if sessions.contains_key(&session_tag) {
                        let session = sessions.get_mut(&session_tag).unwrap();
                        plaintext = session.decrypt(&mut store, &e).unwrap();
                        identity = session.remote_identity.public_key.fingerprint();
                    } else {
                        let (s, p) = Session::init_from_message(&ikp, &mut store, &e).unwrap();
                        identity = s.remote_identity.public_key.fingerprint();
                        sessions.insert(session_tag.to_string(), s);
                        plaintext = p;
                    }
                    let id = ikp.public_key.fingerprint() + &identity;
                    let pt = String::from_utf8(plaintext).unwrap();
                    let msg: LumiMessage = json::decode(&pt).unwrap();
                    let sm = LumiMessageStored {
                        text: msg.text.clone(),
                        group_id: msg.group_id.clone(),
                        identity: identity.clone(),
                    };
                    store_message(&sm, &id);
                    match msg.group_id {
                        Some(id) => {
                            if !group_exists(&id) {
                                let group: LumiGroup = json::decode(&msg.text).unwrap();
                                save_group(&group);
                            } else {
                                if sm.text == "/LEAVE" {
                                    let mut group = get_group(&msg.group_id.unwrap()).unwrap();
                                    delete_group(&group);
                                    let mut members = Vec::new();
                                    for member in group.members {
                                        if member != identity {
                                            members.push(member);
                                        }
                                    }
                                    group.members = members;
                                    save_group(&group)
                                }
                                let group: Result<LumiGroup, DecoderError> = json::decode(&msg.text);
                                match group {
                                    Ok(g) => {
                                        let group = get_group(&msg.group_id.unwrap()).unwrap();
                                        delete_group(&group);
                                        save_group(&g);
                                    },
                                    Err(_) => {
                                        store_message(&sm, &(ikp.public_key.fingerprint() + &id.to_hyphenated_string()));
                                    }
                                }
                            }
                        },
                        _ => {}
                    }
                },
                None => {}
            };
        }
    });

    Iron::new(mount).http(("127.0.0.1", get_instance_port())).unwrap();
}

fn store_message(message: &LumiMessageStored, id: &String) {
    let client = redis::Client::open("redis://127.0.0.1/").unwrap();
    let con = client.get_connection().unwrap();
    let _: () = con.rpush(id.clone(), json::encode(&message).unwrap()).unwrap();
}

fn notify_group_leaving(group: &LumiGroup) {
    let config = get_config().unwrap();
    let ikp = get_identity_keypair(&config);
    for member in &group.members {
        if *member != ikp.public_key.fingerprint() {
            let msg = LumiMessage {
                text: "/LEAVE".to_string(),
                group_id: Some(group.id),
            };
            let req = LumiMessageSendRequest {
                message: msg,
                to: member.clone(),
            };
            queue_message(&req);
        }
    }
}

fn notify_group_update(group: &LumiGroup) {
    let config = get_config().unwrap();
    let ikp = get_identity_keypair(&config);
    for member in &group.members {
        if *member != ikp.public_key.fingerprint() {
            let msg = LumiMessage {
                text: json::encode(group).unwrap(),
                group_id: Some(group.id),
            };
            let req = LumiMessageSendRequest {
                message: msg,
                to: member.clone(),
            };
            queue_message(&req);
        }
    }
}

fn get_groups() -> Vec<LumiGroup> {
    let config = get_config().unwrap();
    let ikp = get_identity_keypair(&config);
    let client = redis::Client::open("redis://127.0.0.1/").unwrap();
    let con = client.get_connection().unwrap();
    let gs: Vec<String> = con.smembers(ikp.public_key.fingerprint() + "groups").unwrap();
    let mut groups = Vec::new();
    for g in gs {
        let group: LumiGroup = json::decode(&g).unwrap();
        groups.push(group);
    }
    groups
}

fn group_exists(id: &Uuid) -> bool {
    let groups = get_groups();
    for group in groups {
        if group.id == *id {
            return true
        }
    }
    false
}


fn get_group(id: &Uuid) -> Option<LumiGroup> {
    let groups = get_groups();
    for group in groups {
        if group.id == *id {
            return Some(group)
        }
    }
    None
}

fn save_group(group: &LumiGroup) {
    let config = get_config().unwrap();
    let ikp = get_identity_keypair(&config);
    let client = redis::Client::open("redis://127.0.0.1/").unwrap();
    let con = client.get_connection().unwrap();
    let _: () = con.sadd(
        ikp.public_key.fingerprint() + "groups",
        group.to_json()).unwrap();
}

fn delete_group_messages(group: &LumiGroup) {
    let config = get_config().unwrap();
    let ikp = get_identity_keypair(&config);
    let client = redis::Client::open("redis://127.0.0.1/").unwrap();
    let con = client.get_connection().unwrap();
    let _: () = con.del(ikp.public_key.fingerprint() + &group.id.to_hyphenated_string()).unwrap();
}

fn delete_group(group: &LumiGroup) {
    let config = get_config().unwrap();
    let ikp = get_identity_keypair(&config);
    let client = redis::Client::open("redis://127.0.0.1/").unwrap();
    let con = client.get_connection().unwrap();
    let _: () = con.srem(
        ikp.public_key.fingerprint() + "groups",
        group.to_json()).unwrap();
}

fn get_instance_port() -> u16 {
    let port_str = &env::var("LUMI_PORT").unwrap();
    let port = u16::from_str(port_str).unwrap();
    port
}

fn queue_message(message: &LumiMessageSendRequest) {
    let config = get_config().unwrap();
    let ikp = get_identity_keypair(&config);
    let id = ikp.public_key.fingerprint() + "-send-queue";
    let client = redis::Client::open("redis://127.0.0.1/").unwrap();
    let con = client.get_connection().unwrap();
    let _: () = con.rpush(id, message.to_json()).unwrap();
}

fn get_stored_messages(id: &String) -> Vec<LumiMessageStored> {
    let client = redis::Client::open("redis://127.0.0.1/").unwrap();
    let con = client.get_connection().unwrap();
    let ms: Vec<String> = con.lrange(id.clone(), 0, -1).unwrap();
    let mut messages: Vec<LumiMessageStored> = Vec::new();
    for m in ms.clone() {
        let decoded: LumiMessageStored = json::decode(&m).unwrap();
        messages.push(decoded);
    }
    messages
}

fn send_message(message: &String, session: &mut Session) {
    let envelope = session.encrypt(&message.trim().as_bytes()).into_owned();
    let mut map = BTreeMap::new();
    map.insert("mac", envelope.mac.sig.0.to_vec().to_hex());
    map.insert("message_enc", envelope.message_enc.to_hex());
    match envelope.message {
        Message::Keyed(m) => {
            map.insert("prekey_id", m.prekey_id.0.to_string());
            map.insert("base_key", m.base_key.into_owned().0.to_hex());
            map.insert("identity_key", m.identity_key.fingerprint());

            map.insert("session_tag", m.message.session_tag.tag.to_hex());
            map.insert("counter", m.message.counter.0.to_string());
            map.insert("prev_counter", m.message.prev_counter.0.to_string());
            map.insert("ratchet_key", m.message.ratchet_key.into_owned().fingerprint());
            map.insert("cipher_text", m.message.cipher_text.to_hex());
        },
        Message::Plain(m) => {
            map.insert("session_tag", m.session_tag.tag.to_hex());
            map.insert("counter", m.counter.0.to_string());
            map.insert("prev_counter", m.prev_counter.0.to_string());
            map.insert("ratchet_key", m.ratchet_key.into_owned().fingerprint());
            map.insert("cipher_text", m.cipher_text.to_hex());

        }
    }
    let mimetype_json = Mime(TopLevel::Application, SubLevel::Json, vec![]);
    let json_quality = QualityItem::new(mimetype_json.clone(), Quality(1));
    let mut headers = Headers::new();
    headers.set(Accept(vec![json_quality]));
    headers.set(ContentType(mimetype_json.clone()));
    let url = [
        "http://127.0.0.1:5000/",
        &*session.remote_identity.public_key.fingerprint(),
        "/messages/"
            ].join("");
    let client = Client::new();
    let res = client.post(&url)
        .headers(headers.clone())
        .body(&serde_json::to_string(&map).unwrap())
        .send()
        .unwrap();
    assert_eq!(res.status, hyper::Ok);
}

fn get_others_identities() -> Vec<String> {
    let config = get_config().unwrap();
    let ikp = get_identity_keypair(&config);
    let ids = get_identities();
    let mut identities = Vec::new();
    for id in ids {
        if id != ikp.public_key.fingerprint() {
            identities.push(id);
        }
    }
    identities
}

fn get_identities() -> Vec<String> {
    let client = Client::new();
    let mut headers = Headers::new();
    let mimetype_json = Mime(TopLevel::Application, SubLevel::Json, vec![]);
    let json_quality = QualityItem::new(mimetype_json.clone(), Quality(1));
    headers.set(Accept(vec![json_quality]));
    headers.set(ContentType(mimetype_json.clone()));
    let mut res = client.get("http://127.0.0.1:5000/identities/")
        .headers(headers.clone())
        .send()
        .unwrap();
    let mut body = String::new();
    res.read_to_string(&mut body).unwrap();
    let identities: BTreeMap<String, Vec<String>> = serde_json::from_str(&body).unwrap();
    identities.get("identities").unwrap().clone()
}

fn get_oldest_message<'r>(identity: &IdentityKeyPair) -> Option<Envelope<'r>> {
    let url = [
        "http://127.0.0.1:5000/",
        &*identity.public_key.public_key.fingerprint(),
        "/messages/oldest/"
            ].join("");
    let client = Client::new();
    let mut res = client.get(&url)
        .send()
        .unwrap();
    match res.status {
        hyper::Ok => {
            let mut body = String::new();
            res.read_to_string(&mut body).unwrap();
            let map: BTreeMap<String, String> = serde_json::from_str(&body).unwrap();
            let envelope;
            if map.contains_key("prekey_id") {
                let session_tag = SessionTag {
                    tag: map.get("session_tag").unwrap().from_hex().unwrap()
                };
                let counter = Counter(map.get("counter").unwrap().parse::<u32>().unwrap());
                let prev_counter = Counter(map.get("prev_counter").unwrap().parse::<u32>().unwrap());
                let mut buffer = [0u8; 32];
                let pub_buffer = map.get("ratchet_key").unwrap().from_hex().unwrap();
                for i in 0..32 {
                    buffer[i] = pub_buffer[i];
                }
                let ratchet_key = PublicKey(buffer);
                let cipher_text = map.get("cipher_text").unwrap().from_hex().unwrap();
                let cipher_message = CipherMessage {
                    session_tag: Cow::Owned(session_tag),
                    counter: counter,
                    prev_counter: prev_counter,
                    ratchet_key: Cow::Owned(ratchet_key),
                    cipher_text: cipher_text
                };
                let prekey_id = PreKeyId(map.get("prekey_id").unwrap().parse::<u16>().unwrap());
                let base_buffer = map.get("base_key").unwrap().from_hex().unwrap();
                for i in 0..32 {
                    buffer[i] = base_buffer[i];
                }
                let base_key = PublicKey(buffer);
                let ident_buffer = map.get("identity_key").unwrap().from_hex().unwrap();
                for i in 0..32 {
                    buffer[i] = ident_buffer[i];
                }
                let identity_key = PublicKey(buffer);
                let prekey_message = PreKeyMessage {
                    prekey_id: prekey_id,
                    base_key: Cow::Owned(base_key),
                    identity_key: Cow::Owned(IdentityKey { public_key: identity_key }),
                    message: cipher_message
                };
                let mac_buffer = map.get("mac").unwrap().from_hex().unwrap();
                for i in 0..32 {
                    buffer[i] = mac_buffer[i];
                }
                let message_enc = map.get("message_enc").unwrap().from_hex().unwrap();
                envelope = Envelope {
                    mac: Mac { sig: Tag(buffer) },
                    message: Message::Keyed(prekey_message),
                    message_enc: message_enc
                }
            } else {
                let session_tag = SessionTag {
                    tag: map.get("session_tag").unwrap().from_hex().unwrap()
                };
                let counter = Counter(map.get("counter").unwrap().parse::<u32>().unwrap());
                let prev_counter = Counter(map.get("prev_counter").unwrap().parse::<u32>().unwrap());
                let mut buffer = [0u8; 32];
                let pub_buffer = map.get("ratchet_key").unwrap().from_hex().unwrap();
                for i in 0..32 {
                    buffer[i] = pub_buffer[i];
                }
                let ratchet_key = PublicKey(buffer);
                let cipher_text = map.get("cipher_text").unwrap().from_hex().unwrap();
                let cipher_message = CipherMessage {
                    session_tag: Cow::Owned(session_tag),
                    counter: counter,
                    prev_counter: prev_counter,
                    ratchet_key: Cow::Owned(ratchet_key),
                    cipher_text: cipher_text
                };
                let message_enc = map.get("message_enc").unwrap().from_hex().unwrap();
                envelope = Envelope {
                    mac: Mac { sig: Tag(buffer) },
                    message: Message::Plain(cipher_message),
                    message_enc: message_enc
                }

            }
            Some(envelope)
        },
        _ => None
    }
}
