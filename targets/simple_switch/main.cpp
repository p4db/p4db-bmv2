/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

/* Switch instance */

#include <bm/bm_runtime/bm_runtime.h>
#include <bm/bm_sim/target_parser.h>

#include "simple_switch.h"

#include "SimpleSwitch_server.ipp"

using bm::TargetParserBasic;

static SimpleSwitch *simple_switch;
static TargetParserBasic *target_parser;

static const std::string cp_ip_opt_name = "controller-ip";
static const std::string cp_ip_opt_help = "ONOS-BMv2 controller IP address";
static const std::string cp_port_opt_name = "controller-port";
static const std::string cp_port_opt_help = "ONOS-BMv2 controller port";

int
main(int argc, char* argv[]) {

  target_parser = new TargetParserBasic();
  target_parser->add_string_option(cp_ip_opt_name, cp_ip_opt_help);
  target_parser->add_int_option(cp_port_opt_name, cp_port_opt_help);

  simple_switch = new SimpleSwitch();
    
  int status = simple_switch->init_from_command_line_options(argc, argv, target_parser);

  if (status != 0) { 
    std::cout<<12131<<std::endl;
    std::exit(status);
  }
  std::string cp_ip;
  int cp_port;

  target_parser->get_string_option(cp_ip_opt_name, &cp_ip);
  target_parser->get_int_option(cp_port_opt_name, &cp_port);
  simple_switch->init_cp_client(cp_ip, cp_port);

  int thrift_port = simple_switch->get_runtime_port();

  bm_runtime::start_server(simple_switch, thrift_port);

  // 3rd template argument could just as well be SimpleSwitch
  bm_runtime::add_service<SimpleSwitchHandler, SimpleSwitchProcessor, Switch>(
    "simple_switch");
  simple_switch->start_and_return();

  while (true) std::this_thread::sleep_for(std::chrono::seconds(100));

  return 0;
}
