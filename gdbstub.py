"""
This module will read gdb remote protocol sniff and print it in req/resp pair
may be translate it later
The protocol sniff is recorded by
cat pipeline | nc -m 1 -l 2345 -k | tee -a inflow | nc localhost 1234 | tee -a outflow 1> pipeline 
"""


def msgs(stream):
    """Read messages from stream/str
    >>> list(msgs('+$qSuppted:mprocess+;xmlters=i386;qRelocInsn+#b5+$Hg0#df'))
    ['qSuppted:mprocess+;xmlters=i386;qRelocInsn+', 'Hg0']
    """
    comp = {}
    comp['body'] = ""
    comp['hash'] = ""
    comp['handler'] = None

    def read_msg_head(c):
        if c == '+':
            pass
        elif c == '$':
            comp['handler'] = read_msg_body
        else:
            raise SyntaxError("Invalid msg start char " + c)

    def read_msg_body(c):
        if c != '#':
            comp['body'] += c
        else:
            comp['handler'] = read_msg_sig

    def read_msg_sig(c):
        comp['hash'] += c
        if len(comp['hash']) == 2:
            comp['handler'] = read_msg_head
            comp['hash'] = ""
            return True

    comp['handler'] = read_msg_head
    for c in stream:
        if comp['handler'](c):
            yield comp['body']
            comp['body'] = ""


def main():
    import sys
    if len(sys.argv) != 3:
        exit("Usage: gdbstub.py inflow outflow")

    inflow = open(sys.argv[1]).read()
    outflow = open(sys.argv[2]).read()

    reqs = msgs(inflow)
    resps = msgs(outflow)

    for req in reqs:
        print "Req: "
        print req
        print "Resp: "
        print resps.next()

if __name__ == "__main__":
    main()
