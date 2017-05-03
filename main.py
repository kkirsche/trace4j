#!venv/bin/python3

from argparse import ArgumentParser
from parser import Traceroute


def main(args):
    t = Traceroute(args.cidr)
    t.traceroute()


if __name__ == '__main__':
    parser = ArgumentParser(description=('Run a traceroute and convert the '
                                         'output into a Neo4j graph.'))
    parser.add_argument('cidr', type=str, help='CIDR netblock to traceroute')
    args = parser.parse_args()
    main(args)
