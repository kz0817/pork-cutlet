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

    pkt_map = {}

    def __init__(self, line):
       self.time = None
       self.src = None
       self.dst = None
       self.seq = None
       self.ack = None
       self.win = None
       self.len = None
       self.ack_pkt = None
       self.avail = False

       self.__parse(line)

    def __parse(self, line):

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

        self.__resister_seq()
        self.__associate_related_pkt()

        self.avail = self.seq and self.ack and self.len

    def __resister_seq(self):
        if self.seq is None:
            return None
        if self.len is None:
            return None
        ack_number = self.seq + self.len
        key = self.__make_key(self.src, ack_number)
        if key is not None:
            self.pkt_map[key] = self

    def __associate_related_pkt(self):
        if self.dst is None:
            return
        if self.ack is None:
            return
        key = self.__make_key(self.dst, self.ack)
        if key not in self.pkt_map:
            return
        related_pkt = self.pkt_map[key]
        related_pkt.ack_pkt = self

    def __make_key(self, name, num):
        return '%s:%s' % (name, num)


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
    return pkts


class Status(object):
    def __init__(self):
        self.cnt = 0
        self.ack_cnt = 0
        self.ack_time_sum = datetime.timedelta()
        self.size_sum = 0.0
        self.prev_pkt_time = None
        self.pkt_interval_sum = datetime.timedelta()

    def __add_ack_time(self, pkt):
        if pkt.ack_pkt is None:
            return
        self.ack_cnt += 1
        self.ack_time_sum += (pkt.ack_pkt.time - pkt.time)

    def __add_pkt_time(self, pkt):
        if self.prev_pkt_time is not None:
            self.pkt_interval_sum += (pkt.time - self.prev_pkt_time)
        self.prev_pkt_time = pkt.time

    def add_pkt(self, pkt):
        self.cnt += 1
        self.size_sum += pkt.len
        self.__add_pkt_time(pkt)
        self.__add_ack_time(pkt)

    def get_avg_ack_time(self):
        if self.ack_cnt == 0:
            return 0
        return (self.ack_time_sum / self.ack_cnt).total_seconds()


    def get_avg_size(self):
        if self.cnt == 0:
            return 0;
        return self.size_sum / self.cnt

    def get_avg_pkt_interval(self):
        if self.cnt <= 1:
            return 0.0
        return (self.pkt_interval_sum / (self.cnt - 1)).total_seconds()


def calc_stat(pkts):

    def make_comb_key(src, dst):
        return '%16s -> %16s' % (src, dst)

    cnt = 0;
    stats = {}
    for pkt in pkts:
        if not pkt.avail:
            continue

        key = make_comb_key(pkt.src, pkt.dst)
        if key not in stats:
            stats[key] = Status()
        stat = stats[key]
        stat.add_pkt(pkt)

    return stats

def show_stats(stats):
    for key in stats:
        st = stats[key]
        print('%s   Avg time to ACK(ms): %10.3f (%6s/%6s)  Avg size: %5d  Avg interval(ms): %10.3f '% \
              (key, st.get_avg_ack_time()*1e3, st.ack_cnt, st.cnt,
               st.get_avg_size(), st.get_avg_pkt_interval()*1e3))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('infile', type=argparse.FileType('r'));
    args = parser.parse_args()
    pkts = parse(args)
    stats = calc_stat(pkts)
    show_stats(stats)

if __name__ == '__main__':
    main()
