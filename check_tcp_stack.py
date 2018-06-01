#!/usr/bin/env python
# Creator: Nicolas Magliaro  - Version: 0.7
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
        "-b", "--buffers", dest="buffer", default=False, action="store", type="string", help="Return buffers values. Use with -p for specific proto")
    parser.add_option(
        "-t", dest="trigger", action="store_true", help="Return sysctl values")
    parser.add_option(
        "-l", dest="loss", action="store_true", help="Return UDP packet loss sum")
    parser.add_option(
        "-m", dest="memory", action="store_true", help="Return UDP packet in memory")
    parser.add_option(
        "-u", dest="use", action="store_true", help="Return UDP packet in use")
    parser.add_option(
        "-o", dest="orphans", action="store_true", help="Return TCP orphans packet")

    (options, args) = parser.parse_args()

    return options

class Queues:
    """
        Args: takes exactly 1 param as a dictionary with the Optparse arguments to create the Obj in memory
    """
    def __init__(self, opt):

        self.opt                    = opt
        self.proto                  = self.opt.proto
        self.state                  = self.opt.state
        self.queue                  = self.opt.queue
        self.trigger                = self.opt.trigger
        self.orphans                = self.opt.orphans
        self.buffer                 = self.opt.buffer
        self.cat_proc               = self.__open_queue_conn()
        self.conn_states            = self.__set_conn_by_state()
        self.socket_stats           = self.__get_socket_stats()
        self.tcp_buffer_thresholds  = open("/proc/sys/net/ipv4/tcp_mem", "r").readlines()
        self.udp_buffer_thresholds  = open("/proc/sys/net/ipv4/udp_mem", "r").readlines()

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

    # Return sockets in memory
    def get_used_memory(self):
        process = self.socket_stats
        if self.proto == "udp":
            return int(process[2].split(' ')[-1])
        if self.proto == "tcp":
            return int(process[1].split(' ')[-1])
        return

    # Return UDP sockets in use
    def get_sockets_in_use(self):
        process = self.socket_stats
        if self.proto == "udp":
            return int(process[2].split()[2])
        if self.proto == "tcp":
            return int(process[1].split()[2])
        return

    # Return TCP orphans
    def get_tcp_orphans(self):
        procfile = self.socket_stats
        return int(procfile[1].split(' ')[4])

    def get_buffer_threshold(self,th):
        """
        Param = low_threshold. Return the tcp_mem variable in the kernel for the memory usage by different TCP sockets.
        Param = press_threshold. Return at which point to start pressuring memory usage down. 
        Param = max_threshold. Return how many memory pages it may use maximally in the kernel 
        """
        if self.proto == "udp":
            if th == "low_threshold":
                return int(self.udp_buffer_thresholds[0].split('\t')[0])
            if th == "press_threshold":
                return int(self.udp_buffer_thresholds[0].split('\t')[1])
            if th == "max_threshold":
                return int(self.udp_buffer_thresholds[0].split('\t')[2])
        if self.proto == "tcp":
            if th == "low_threshold":
                return int(self.tcp_buffer_thresholds[0].split('\t')[0])
            if th == "press_threshold":
                return int(self.tcp_buffer_thresholds[0].split('\t')[1])
            if th == "max_threshold":
                return int(self.tcp_buffer_thresholds[0].split('\t')[2])
        return

class Run:
    """
    Args1: List: OptParse()
    Implement the run() method
    """
    def __init__(self, opts = []):
        self.opts = opts
        self.connections = Queues(self.opts)

    def run(self):
        if not self.opts.queue and not self.opts.state and not self.opts.buffer and self.opts.loss == None and self.opts.orphans == None and self.opts.memory == None and self.opts.use == None:
            print self.connections.total_sockets()
        elif self.opts.proto.lower() == "tcp":
            if self.opts.state and self.opts.state is not None:
                print self.connections.get_count_by_state(opts.state)
                sys.exit()
            if self.opts.queue and self.opts.queue is not None and not self.opts.trigger:
                print self.connections.tcp_queues_trigger()
                sys.exit()
            if self.opts.trigger and self.opts.queue:
                print self.connections.get_queue_value()
                sys.exit()
            if self.opts.orphans:
                print self.connections.get_tcp_orphans()
                sys.exit()
            if self.opts.buffer:
                print self.connections.get_buffer_threshold(self.opts.buffer)
                sys.exit()
            if self.opts.memory:
                print self.connections.get_used_memory()
                sys.exit()
            if self.opts.use:
                print self.connections.get_sockets_in_use()
                sys.exit()
            print self.connections.json_conn_list_count()
        
        elif self.opts.proto.lower() == "udp":
            if self.opts.loss:
                print self.connections.get_pkt_loss_sum()
                sys.exit()
            if self.opts.memory:
                print self.connections.get_used_memory()
                sys.exit()
            if self.opts.use:
                print self.connections.get_sockets_in_use()
                sys.exit()
            if self.opts.buffer:
                print self.connections.get_buffer_threshold(self.opts.buffer)
                sys.exit()
        else:
            print None
if __name__ == "__main__":
    opts = _parse_args()
    run = Run(opts).run
    run()
