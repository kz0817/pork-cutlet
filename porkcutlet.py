#!/usr/bin/env python3

import argparse
import datetime

class Utils(object):
    @staticmethod
    def to_datetime(str_time):
      return datetime.datetime.strptime(str_time, '%H:%M:%S.%f')

    @staticmethod
    def get_value(array, label):
        try:
            idx = array.index(label)
            if idx == len(array) - 1:
                return None
            return array[idx+1].strip(',');
        except ValueError:
            return None

    def to_int_or_none(valstr):
        try:
            return int(valstr)
        except ValueError:
            return None

    @staticmethod
    def get_seq(array, label):
        val = Utils.get_value(array, label)
        if val is None:
            return None
        words = val.split(':')
        return Utils.to_int_or_none(words[0])

    @staticmethod
    def get_int(array, label):
        val = Utils.get_value(array, label)
        if val is None:
            return None
        return Utils.to_int_or_none(val)

class PktInfo(object):
    def __init__(self, line):
       self.time = None
       self.src = None
       self.dst = None
       self.seq = None
       self.ack = None
       self.win = None
       self.len = None

       self.__get_base_info(line)

    def __get_base_info(self, line):

        # [exmpale] 07:03:56.449539 IP 192.168.5.3.5201 > 10.8.0.10.50194:
        NUM_MIN_ELEM = len(['time', 'IP', 'SRC', '>', 'DST:'])
        words = line.split()
        if len(words) < NUM_MIN_ELEM:
            return
        self.time = Utils.to_datetime(words[0])
        self.src = words[2]
        self.dst = words[4][0:-1]

        self.seq = Utils.get_seq(words, 'seq');
        self.ack = Utils.get_int(words, 'ack');
        self.win = Utils.get_int(words, 'win');
        self.len = Utils.get_int(words, 'length');

    def __str__(self):
        s = '%s src: %s, dst: %s, seq: %s, ack: %s, len: %s, win: %s' % \
            (self.time, self.src, self.dst, self.seq, self.ack, \
             self.len, self.win)
        return s


def parse(args):
    pkts = []
    for line in args.infile:
        pkt_info = PktInfo(line)
        if pkt_info.time is None:
            continue
        pkts.append(pkt_info)
    print('Parsed: %d pkts' % len(pkts))

def main():
   parser = argparse.ArgumentParser()
   parser.add_argument('infile', type=argparse.FileType('r'));
   args = parser.parse_args()
   parse(args)

if __name__ == '__main__':
    main()
