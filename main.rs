mod common;
mod data;
mod management;
mod control;
mod ip;
mod forming;
mod state;
mod crypto;

use common::*;
use data::*;
use management::*;
use control::*;
use ip::*;
use forming::*;
use state::*;
use crypto::*;

use std::time::{Instant, Duration};
use std::collections::VecDeque;
use std::collections::HashMap;

use crate::state::Interface;
use crate::common::PHY;

struct Network<'a> {
    interfaces: Vec<Interface<'a>>,
}

fn main() {
    env_logger::init();

    
}