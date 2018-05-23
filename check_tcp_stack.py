#!/usr/bin/env python
# Creator: Nicolas Magliaro  - Version: 0.3
# date: 16/05/2018

import sys
import json
from optparse import OptionParser

def _parse_args():

    parser = OptionParser()

    parser.add_option(
        "-p", "--proto", dest="proto", default='tcp', action="store", type="string", help="Define protocol TCP||UDP")
    parser.add_option(
        "-s", "--state", dest="state", default=False, action="store", type="string", help="Describe the state of connection")
    parser.add_option(
        "-q", "--queue", dest="queue", default=False, action="store", type="string", help="Define queue trigger SYN||ACCEPTED")
    parser.add_option(
        "-t", dest="trigger", action="store_true", help="Return sysctl values")
    parser.add_option(
        "-l", dest="loss", action="store_true", help="Return UDP packet loss sum")
    parser.add_option(
        "-m", dest="memory", action="store_true", help="Return UDP packet in memory")
    parser.add_option(
        "-u", dest="use", action="store_true", help="Return UDP packet in use")

    (options, args) = parser.parse_args()

    return options

class Queues:
    """
        Args: takes exactly 1 param as a dictionary with the Optparse arguments to create the Obj in memory
    """
    def __init__(self, opt):

        self.opt                = opt
        self.proto              = self.opt.proto
        self.state              = self.opt.state
        self.queue              = self.opt.queue
        self.trigger            = self.opt.trigger

        self.cat_proc           = self.__open_queue_conn()
        self.conn_states        = self.__set_conn_by_state()
        self.socket_stats       = self.__get_socket_stats()

        # TCP States
        self.tcp_states  = {
                            'TCP_ESTABLISHED':'01',
                            'TCP_SYN_SENT':'02',
                            'TCP_SYN_RECV':'03',
                            'TCP_FIN_WAIT1':'04',
                            'TCP_FIN_WAIT2':'05',
                            'TCP_TIME_WAIT':'06',
                            'TCP_CLOSE':'07',
                            'TCP_CLOSE_WAIT':'08',
                            'TCP_LAST_ACK':'09',
                            'TCP_LISTEN':'0A',
                            'TCP_CLOSING':'0B'
                            }
    
        # UDP States
        self.udp_states  = {}

    # Read Kernel connection list
    def __open_queue_conn( self ):
        procfile = open("/proc/net/"+self.proto, "r").readlines()[1:]
        return procfile

    # Return a list of the states for all connections
    def __set_conn_by_state(self):
        conn_list = []
        procfile = self.cat_proc
        for line in procfile:
            line = line.split(': ')[1].split(' ')[2]
            conn_list.append(line)
        return conn_list

    # Return a count of the states by connection
    def __filter_count_conn_by_state(self, state):
        if self.conn_states:
            return self.conn_states.count(state)
        return
    def __get_socket_stats(self):
        procfile = open("/proc/net/sockstat", "r").readlines()
        return procfile

    # Return total socket created
    def total_sockets(self):
        procfile = self.socket_stats
        return int(procfile[0].split(' ')[-1])

    #Return dict obj with all count ordered by conn type
    def get_conn_by_state(self):
        return self.conn_states    

    # Return current total connections 
    def get_total_count_conn(self):
        return len(self.cat_proc)

    # Return the count of socket with state given
    def get_count_by_state(self, state):
        state = self.tcp_states[state]
        return self.__filter_count_conn_by_state(state)

    # Return a json obj with a count of all connection
    def json_conn_list_count(self):
        json_obj = {}
        for k,v in self.tcp_states.iteritems():
            json_obj[k] = self.conn_states.count(v)
        json_obj["TOTAL"] = len(self.conn_states)
        return json.dumps(json_obj,sort_keys=True, indent=4)

    # Return the usage of TCP queues
    def tcp_queues_trigger(self):
        queue = self.queue
        if queue.upper() == "SYN":
            queue = "/proc/sys/net/ipv4/tcp_max_syn_backlog"
            procfile = open(queue, "r").readlines()[0]
            return self.__filter_count_conn_by_state( self.tcp_states["TCP_SYN_RECV"] ) * 100 / int( procfile )
        elif queue.upper() == "ACCEPTED":
            queue = "/proc/sys/net/core/somaxconn"
            procfile = open(queue, "r").readlines()[0]
            return self.__filter_count_conn_by_state( self.tcp_states["TCP_ESTABLISHED"] ) * 100 / int( procfile )
        else:
            return

    # Return kernel theshold for Network queues
    def get_queue_value(self):
        queue = self.queue
        if queue.upper() == "SYN":
            queue = "/proc/sys/net/ipv4/tcp_max_syn_backlog"
            procfile = open(queue, "r").readlines()[0]
            return procfile
        elif queue.upper() == "ACCEPTED":
            queue = "/proc/sys/net/core/somaxconn"
            procfile = open(queue, "r").readlines()[0]
            return procfile
        return

    # Return the sum of pkt lost by UDP sockets
    def get_pkt_loss_sum(self):
        a = []
        process = self.__open_queue_conn()
        for p in process:
            f = list(p.split(' '))
            a.append(int([x for x in f if x != '\n' and x != ''][-1]))
        return sum(a)

    # Return UDP sockets in memory
    def get_udp_in_memory(self):
        process = self.socket_stats
        return int(process[2].split(' ')[-1])

    # Return UDP sockets in use
    def get_udp_in_use(self):
        process = self.socket_stats
        return int(process[2].split()[2])


if __name__ == "__main__":
    opts = _parse_args()
    connections = Queues(opts)
    if not opts.queue and not opts.state and opts.loss == None and opts.memory == None and opts.use == None:
        print connections.total_sockets()
    elif opts.proto.lower() == "tcp":
        if opts.state and opts.state is not None:
            print connections.get_count_by_state(opts.state)
            sys.exit()
        if opts.queue and opts.queue is not None and not opts.trigger:
            print connections.tcp_queues_trigger()
            sys.exit()
        if opts.trigger and opts.queue:
            print connections.get_queue_value()
            sys.exit()
        print connections.json_conn_list_count()
    elif opts.proto.lower() == "udp":
        if opts.loss:
            print connections.get_pkt_loss_sum()
            sys.exit()
        if opts.memory:
            print connections.get_udp_in_memory()
            sys.exit()
        if opts.use:
            print connections.get_udp_in_use()
            sys.exit()
    else:
        print None
