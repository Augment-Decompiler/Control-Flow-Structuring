import ida_lines
import ida_idaapi
import ida_kernwin
import ida_hexrays
import ida_hexrays as hr

from idautils import * 
from idaapi import * 
from idc import *

'''
const mopt_t
  mop_z   = 0,  ///< none
  mop_r   = 1,  ///< register (they exist until MMAT_LVARS)
  mop_n   = 2,  ///< immediate number constant
  mop_str = 3,  ///< immediate string constant
  mop_d   = 4,  ///< result of another instruction
  mop_S   = 5,  ///< local stack variable (they exist until MMAT_LVARS)
  mop_v   = 6,  ///< global variable
  mop_b   = 7,  ///< micro basic block (mblock_t)
  mop_f   = 8,  ///< list of arguments
  mop_l   = 9,  ///< local variable
  mop_a   = 10, ///< mop_addr_t: address of operand (mop_l, mop_v, mop_S, mop_r)
  mop_h   = 11, ///< helper function
  mop_c   = 12, ///< mcases
  mop_fn  = 13, ///< floating point constant
  mop_p   = 14, ///< operand pair
  mop_sc  = 15; ///< scattered
  '''



#------------------------------------------------------------------------------
#  解析mlist ，maybe作为可选项
#------------------------------------------------------------------------------
def parse_mlist(must, maybe=None):
    print(must.reg.dstr())
    for i in must.reg:
        print("{} reg count : {}".format(i ,must.reg.count(i)))
    print("0x%x"%must.mem.getivl(0).off)
    print(must.mem.getivl(0).size)
    
    must_regs = must.reg.dstr().split(",")
    must_mems = must.mem.dstr().split(",")
    maybe_regs = maybe.reg.dstr().split(",") if maybe else []
    maybe_mems = maybe.mem.dstr().split(",") if maybe else []
    for splits in [must_regs, must_mems, maybe_regs, maybe_mems]:
       splits[:] = list(filter(None, splits))[:] # lol
    maybe_regs = list(filter(lambda x: x not in must_regs, maybe_regs))
    maybe_mems = list(filter(lambda x: x not in must_mems, maybe_mems))
    return must_regs,must_mems

#-----------------------------------------------------------------------------
# Hex-Rays Util
#-----------------------------------------------------------------------------

def get_CodeSnippet_microcode(addrRange, maturity):
    mbr = hr.mba_ranges_t()
    mbr.ranges.push_back(range_t(addrRange.start, addrRange.end)) 
    #mbr = ida_hexrays.mba_ranges_t(func)
    hf = ida_hexrays.hexrays_failure_t()
    ml = ida_hexrays.mlist_t()
    ida_hexrays.mark_cfunc_dirty(addrRange.start)
    mba = ida_hexrays.gen_microcode(mbr, hf, ml, ida_hexrays.DECOMP_NO_WAIT, maturity)
    if not mba:
        print("0x%08X: %s" % (hf.errea, hf.desc()))
        return None
    return mba
    


def get_func_microcode(func, maturity):
    """
    Return the mba_t of the given function at the specified maturity.
    """
    mbr = ida_hexrays.mba_ranges_t(func)
    hf = ida_hexrays.hexrays_failure_t()
    ml = ida_hexrays.mlist_t()
    ida_hexrays.mark_cfunc_dirty(func.start_ea)
    mba = ida_hexrays.gen_microcode(mbr, hf, ml, ida_hexrays.DECOMP_NO_WAIT, maturity)
    if not mba:
        print("0x%08X: %s" % (hf.errea, hf.desc()))
        return None
    return mba

def get_all_vdui():
    """
    Return every visible vdui_t (Hex-Rays window).
    """
    found = {}

    # TODO: A-Z.. eh good enough
    for widget_title in ["Pseudocode-%c" % chr(0x41+i) for i in range(0, 26)]:

        # try to find the hexrays widget of the given name
        widget = ida_kernwin.find_widget(widget_title)
        if not widget:
            continue

        # make sure the widget looks in-use
        vdui = ida_hexrays.get_widget_vdui(widget)
        if not (vdui and vdui.visible):
            continue

        found[widget_title] = vdui

    return found

#-----------------------------------------------------------------------------
# Microcode Util
#-----------------------------------------------------------------------------

MMAT = sorted([(getattr(ida_hexrays, x), x) for x in filter(lambda y: y.startswith('MMAT_'), dir(ida_hexrays))])[1:]
MOPT = [(getattr(ida_hexrays, x), x) for x in filter(lambda y: y.startswith('mop_'), dir(ida_hexrays))]
MCODE = sorted([(getattr(ida_hexrays, x), x) for x in filter(lambda y: y.startswith('m_'), dir(ida_hexrays))])

class MatDelta:
    INCREASING = 1
    NEUTRAL = 0
    DECREASING = -1

def get_mcode_name(mcode):
    """
    Return the name of the given mcode_t.
    """
    for value, name in MCODE:
        if mcode == value:
            return name
    return None

def get_mopt_name(mopt):
    """
    Return the name of the given mopt_t.
    """
    for value, name in MOPT:
        if mopt == value:
            return name
    return None

def get_mmat(mmat_name):
    """
    Return the mba_maturity_t for the given maturity name.
    """
    for value, name in MMAT:
        if name == mmat_name:
            return value
    return None

def get_mmat_name(mmat):
    """
    Return the maturity name of the given mba_maturity_t.
    """
    for value, name in MMAT:
        if value == mmat:
            return name
    return None

def get_mmat_levels():
    """
    Return a list of the microcode maturity levels.
    """
    return list(map(lambda x: x[0], MMAT))

def diff_mmat(mmat_src, mmat_dst):
    """
    Return an enum indicating maturity growth.
    """
    direction = mmat_dst - mmat_src
    if direction > 0:
        return MatDelta.INCREASING
    if direction < 0:
        return MatDelta.DECREASING
    return MatDelta.NEUTRAL

#------------------------------------------------------------------------------
# CTree Util
#------------------------------------------------------------------------------

def map_line2citem(decompilation_text):
    """
    Map decompilation line numbers to citems.

    This function allows us to build a relationship between citems in the
    ctree and specific lines in the hexrays decompilation text.

    Output:
        +- line2citem:
        |    a map keyed with line numbers, holding sets of citem indexes
        |
        |      eg: { int(line_number): sets(citem_indexes), ... }
        '
    """
    line2citem = {}

    #
    # it turns out that citem indexes are actually stored inline with the
    # decompilation text output, hidden behind COLOR_ADDR tokens.
    #
    # here we pass each line of raw decompilation text to our crappy lexer,
    # extracting any COLOR_ADDR tokens as citem indexes
    #

    for line_number in range(decompilation_text.size()):
        line_text = decompilation_text[line_number].line
        line2citem[line_number] = lex_citem_indexes(line_text)

    return line2citem

def lex_citem_indexes(line):
    """
    Lex all ctree item indexes from a given line of text.

    The HexRays decompiler output contains invisible text tokens that can
    be used to attribute spans of text to the ctree items that produced them.

    This function will simply scrape and return a list of all the these
    tokens (COLOR_ADDR) which contain item indexes into the ctree.
    """
    i = 0
    indexes = []
    line_length = len(line)

    # lex COLOR_ADDR tokens from the line of text
    while i < line_length:

        # does this character mark the start of a new COLOR_* token?
        if line[i] == ida_lines.COLOR_ON:

            # yes, so move past the COLOR_ON byte
            i += 1

            # is this sequence for a COLOR_ADDR?
            if ord(line[i]) == ida_lines.COLOR_ADDR:

                # yes, so move past the COLOR_ADDR byte
                i += 1

                #
                # A COLOR_ADDR token is followed by either 8, or 16 characters
                # (a hex encoded number) that represents an address/pointer.
                # in this context, it is actually the index number of a citem
                #

                ctree_anchor = int(line[i:i+ida_lines.COLOR_ADDR_SIZE], 16)
                if (ctree_anchor & ida_hexrays.ANCHOR_MASK) != ida_hexrays.ANCHOR_CITEM:
                    continue

                i += ida_lines.COLOR_ADDR_SIZE

                # save the extracted citem index
                indexes.append(ctree_anchor)

                # skip to the next iteration as i has moved
                continue

        # nothing we care about happened, keep lexing forward
        i += 1

    # return all the citem indexes extracted from this line of text
    return indexes

def map_line2ea(cfunc, line2citem):
    """
    Map decompilation line numbers to addresses.
    """
    line2ea = {}
    treeitems = cfunc.treeitems
    function_address = cfunc.entry_ea

    #
    # prior to this function, a line2citem map was built to tell us which
    # citems reside on any given line of text in the decompilation output.
    #
    # now, we walk through this line2citem map one 'line_number' at a time in
    # an effort to retrieve the addresses from each citem
    #

    for line_number, citem_indexes in line2citem.items():
        addresses = set()

        #
        # we are at the level of a single line (line_number). we now consume
        # its set of citems (citem_indexes) and extract their addresses
        #

        for index in citem_indexes:

            # get the code address of the given citem
            try:
                item = treeitems[index]
                address = item.ea

                # TODO, ehh, omit these for now (curly braces, basically)
                if item.op == ida_hexrays.cit_block:
                    continue

            # TODO
            except IndexError as e:
                print("BAD INDEX: 0x%08X" % index)
                continue

            # ignore citems with no address
            if address == ida_idaapi.BADADDR:
                continue

            addresses.add(address)

        line2ea[line_number] = list(addresses)

    # TODO explain special case
    if cfunc.mba.last_prolog_ea != ida_idaapi.BADADDR:
        line2ea[0] = list(range(cfunc.mba.entry_ea, cfunc.mba.last_prolog_ea+1))

    # all done, return the computed map
    return line2ea