#!/usr/bin/env python
# Creator: Nicolas Magliaro  - Version: 0.2
# date: 16/05/2018

import sys
import json
from optparse import OptionParser

def _parse_args():
    parser = OptionParser()
    parser.add_option(
        '-p', '--proto', dest='proto', default='tcp', action="store", type="string", help='Define protocol TCP||UDP')
    parser.add_option(
        '-s', '--state', dest='state', default=False, action="store", type="string", help='Describe the state of connection')
    parser.add_option(
        '-q', '--queue', dest='queue', default=False, action="store", type="string", help='Define queue trigger SYN||ACCEPTED')
    parser.add_option(
        '-t', dest='trigger', action='store_true', help='Return sysctl values')

    (options, args) = parser.parse_args()

    return options

class Queues:
    """
    Args: takes exactly 1 param as a dictionary with the Optparse arguments to create the Obj in memory
    """
    def __init__(self, opt):
        self.opt         = opt
        self.proto       = self.opt.proto
        self.state       = self.opt.state
        self.queue       = self.opt.queue
        self.trigger     = self.opt.trigger

        self.cat_proc    = self.__open_queue_conn()
        self.conn_states = self.__set_conn_by_state()

        # TCP States
        self.tcp_states = {
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
        self.udp_states = {}

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

    def get_conn_by_state(self):
        return self.conn_states    

    # Return current total connections 
    def get_total_count_conn(self):
        #procfile = open_queue_conn()
        return len(self.cat_proc)

    # Return a count of the states by connection
    def __filter_count_conn_by_state(self, state):
        if self.conn_states:
            return self.conn_states.count(state)
        return

    def get_count_by_state(self, state):
        state = self.tcp_states[state]
        return self.__filter_count_conn_by_state(state)

    # Return a json obj with a count of all connection
    def json_conn_list_count(self):
        json_obj = {}
        for k,v in self.tcp_states.iteritems():
            json_obj[k] = self.conn_states.count(v)
        json_obj['TOTAL'] = len(self.conn_states)
        return json.dumps(json_obj,sort_keys=True, indent=4)

    # Return the usage of TCP queues
    def tcp_queues_trigger(self):
        queue = self.queue
        if queue.upper() == 'SYN':
            queue = '/proc/sys/net/ipv4/tcp_max_syn_backlog'
            procfile = open(queue, "r").readlines()[0]
            return self.__filter_count_conn_by_state( self.tcp_states['TCP_SYN_RECV'] ) * 100 / int( procfile )
        elif queue.upper() == 'ACCEPTED': 
            queue = '/proc/sys/net/core/somaxconn'
            procfile = open(queue, "r").readlines()[0]
            return self.__filter_count_conn_by_state( self.tcp_states['TCP_ESTABLISHED'] ) * 100 / int( procfile )
        else:
            return

    def get_queue_value(self):
        queue = self.queue
        if queue.upper() == 'SYN':
            queue = '/proc/sys/net/ipv4/tcp_max_syn_backlog'
            procfile = open(queue, "r").readlines()[0]
            return procfile
        elif queue.upper() == 'ACCEPTED': 
            queue = '/proc/sys/net/core/somaxconn'
            procfile = open(queue, "r").readlines()[0]
            return procfile
        return

if __name__ == "__main__":
    opts = _parse_args()
    connections = Queues(opts)
    if opts.proto.lower() == 'tcp':
        if opts.state and opts.state is not None:
            print connections.get_count_by_state(opts.state)
            sys.exit()
        if opts.queue and opts.queue is not None and not opts.trigger:
            print connections.tcp_queues_trigger()
            sys.exit()
        if opts.trigger and opts.queue:
            print connections.get_queue_value()
            sys.exit()
        print json_conn_list_count()
    else:
        print None
