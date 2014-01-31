#!/usr/bin/python
# Java Cache IDX parser
# Version 1.0 - 12 Jan 13 - @bbaskin
# Version 1.1 - 22 Jan 13 - now supports various IDX file versions
# Version 1.2 - 29 Jan 13 - now supports parsing more section 1 data and section 3 manifest
# Version 1.3 -  8 Feb 13 - Rewrote section 2 parsing. Removed all interpretive code (just parse and print whatever is there)
#                Rewrote into subs, added very basic Java Serialization parsing.
#               Added CSV output to display all values. If you want fields, too, search this file for "CSVEDIT" and follow instructions
# Version 1.4 - 17 Jul 13 - Fixed a few bugs from Section 1, now displays Section 1 data.
#               This is mostly useless, as it is also contained in Section 2, but is used to validate data shown in cases of tampering.

# Version 2.0ppc -  Jul 13 - Fixed a few bugs from Section 1, now displays Section 1 data.
#               This is mostly useless, as it is also contained in Section 2, but is used to validate data shown in cases of tampering.

# * Parsing based off source: http://jdk-source-code.googlecode.com/svn/trunk/jdk6u21_src/deploy/src/common/share/classes/com/sun/deploy/cache/CacheEntry.java
# * Some updates based off research by Mark Woan (@woanwave) - https://github.com/woanware/javaidx/tree/master/Documents
# * Thanks to Corey Harrell for providing a version 6.03 file for testing and for initial inspiration:
#        http://journeyintoir.blogspot.com/2011/02/almost-cooked-up-some-java.html

# Views cached Java download history files
# Typically located in %AppData%\LocalLow\Sun\Java\Deployment\Cache
# These files hold critical details for malware infections, especially
# Java related ones, e.g. BlackHole.

import os, sys, argparse
import struct
import sys
import time
import zlib
import pydeep
import hashlib
import magic
import re
__VERSION__ = "2.0"
__602BUFFER__ = 2 # If script fails to parse your 6.02 files, adjust this. It accounts for a dead space in the data
__CSV__ = False

##########################################################
#    Section two contains all download history data
##########################################################
def sec2_parse(data):
    csv_body = ''
    data.seek (128)
    len_URL = struct.unpack(">l", data.read(4))[0]
    data_URL = data.read(len_URL)

    len_IP = struct.unpack(">l", data.read(4))[0]
    data_IP = data.read(len_IP)
    sec2_fields = struct.unpack(">l", data.read(4))[0]
    return {'len_url':len_URL, 'data_url':data_URL,'len_ip':len_IP,'data_ip':data_IP, 'fields':sec2_fields}
        
#############################################################
#    Section two contains all download history data, for 6.02
#   Cache 6.02 files do NOT store IP addresses
#############################################################
def sec2_parse_old(data):
    data.seek (32)
    len_URL = struct.unpack("b", data.read(1))[0]
    data_URL = data.read(len_URL)
    buf = data.read(__602BUFFER__)
    sec2_fields = struct.unpack(">l", data.read(4))[0]
    
    
    sec2 = {'len_url':len_URL, 'data_url':data_URL, 'fields':sec2_fields}        
    # See if section 3 exists
    if data.tell()+3 < filesize:
        sec3_magic, sec3_ver = struct.unpack(">HH", data.read(4))
    if sec3_magic == 0xACED:
        sec3_type = struct.unpack("b", data.read(1))[0]
        if sec3_type == 0x77: #Data block
            throwaway = data.read(1)
            block_len = struct.unpack(">l", data.read(4))[0]
            block_raw = data.read(block_len)
            if block_raw[0:3] == "\x1F\x8B\x08": # Valid GZIP header
                sec3_unc = zlib.decompress(block_raw, 15+32) # Trick to force bitwindow size
                sec2['manifest']=sec3_unc
        return sec2


        
##########################################################
#    Section three contains a copy of the JAR manifest
##########################################################
def sec3_parse(data,sec2_len,sec3_len,filesize):
    data.seek (128+sec2_len)
    sec3_data = data.read(sec3_len)

    if sec3_data[0:3] == "\x1F\x8B\x08": # Valid GZIP header
        sec3_unc = zlib.decompress(sec3_data, 15+32) # Trick to force bitwindow size
        return sec3_unc.strip()

##########################################################
#    Section four contains Code Signer details
#    Written from docs at:
#    http://docs.oracle.com/javase/6/docs/platform/serialization/spec/protocol.html
##########################################################
def sec4_parse(data,sec2_len,sec3_len,filesize):
    unknowns = 0
    data.seek (128 + sec2_len + sec3_len)
    sec4_magic, sec4_ver = struct.unpack(">HH", data.read(4))
    if sec4_magic == 0xACED: # Magic number for Java serialized data, version always appears to be 5
        while not data.tell() == filesize: # If current offset isn't at end of file yet
            if unknowns > 5:
                print "Too many unrecognized bytes. Exiting."
                return
            sec4_type = struct.unpack("B", data.read(1))[0]
            if sec4_type == 0x77: #Data block .. 
                                  #This _should_ parse for 0x78 (ENDDATABLOCK) but Oracle didn't follow their own specs for IDX files.
                block_len = struct.unpack("b", data.read(1))[0]
                block_raw = data.read(block_len)
                if block_raw[0:3] == "\x1F\x8B\x08": # Valid GZIP header
                    sec4_unc = zlib.decompress(block_raw, 15+32) # Trick to force bitwindow size
                    return sec4_unc.encode("hex")
                else:
                    print "Length: %-2d\nData: %-10s\tHex: %s" % (block_len, block_raw.strip(), block_raw.encode("hex"))
            elif sec4_type == 0x73: #Object
                print "[*] Found: Object\n->",
                continue
            elif sec4_type == 0x72: #Class Description
                block_len = struct.unpack(">h", data.read(2))[0]
                block_raw = data.read(block_len)
                return {"classDescritopn":block_raw}
            else:
                print "Unknown serialization opcode found: 0x%X" % sec4_type
                unknowns += 1
        return
        
def parse_idx(fname):
    data=open(fname,'rb')
    filecontent=open(fname,'rb').read()
    filesize = os.path.getsize(fname)
    busy_byte = data.read(1)
    complete_byte = data.read(1)
    cache_ver = struct.unpack(">i", data.read(4))[0]
    idx_file={'filename':fname,'mimetype':"IDX file: %s (IDX File Version %d.%02d)" % (fname, cache_ver / 100, cache_ver - 600)}
    if cache_ver not in (602, 603, 604, 605, 606):
        print "Invalid IDX header found"
        print "Found:    0x%s" % cache_ver

    m = hashlib.md5()
    m.update(filecontent)
    idx_file['md5']=m.digest().encode('hex')
    
    # computing sha1
    s = hashlib.sha1()               
    s.update(filecontent)
    idx_file['sha1']=s.digest().encode('hex')

    # computing ssdeep
    idx_file['ssdeep']=pydeep.hash_buf(filecontent)
    
    # Different IDX cache versions have data in different offsets
    if cache_ver in [602, 603, 604, 605]:
        if cache_ver in [602, 603, 604]:
            data.seek(8)
        elif cache_ver == 605:
            data.seek(6)
        is_shortcut_img = data.read(1)
        content_len = struct.unpack(">l", data.read(4))[0] 
        last_modified_date = struct.unpack(">q", data.read(8))[0]/1000
        expiration_date = struct.unpack(">q", data.read(8))[0]/1000
        validation_date = struct.unpack(">q", data.read(8))[0]/1000
        sec1={}
        sec1['last_modified_date']=time.strftime("%a, %d %b %Y %X GMT", time.gmtime(last_modified_date))
        if expiration_date:
            sec1['expiration_date']=time.strftime("%a, %d %b %Y %X GMT", time.gmtime(expiration_date))
        if validation_date and cache_ver > 602: #While 6.02 technically supports this, every sample I've seen just has 3 null bytes and skips to Section 2
            sec1['validation_date']=time.strftime("%a, %d %b %Y %X GMT", time.gmtime(validation_date))
        
        if cache_ver == 602:
            sec2_len = 1
            sec3_len = 0
            sec4_len = 0
            sec5_len = 0
        elif cache_ver in [603, 604, 605]:
            known_to_be_signed = data.read(1)
            sec2_len = struct.unpack(">i", data.read(4))[0]
            sec3_len = struct.unpack(">i", data.read(4))[0]
            sec4_len = struct.unpack(">i", data.read(4))[0]
            sec5_len = struct.unpack(">i", data.read(4))[0]
            
            blacklist_timestamp = struct.unpack(">q", data.read(8))[0]/1000
            cert_expiration_date = struct.unpack(">q", data.read(8))[0]/1000
            class_verification_status = data.read(1)
            reduced_manifest_length = struct.unpack(">l", data.read(4))[0]
            
            #print "Section 2 length: %d" % sec2_len
            if sec3_len: print "Section 3 length: %d" % sec3_len
            if sec4_len: print "Section 4 length: %d" % sec4_len
            if sec5_len: print "Section 4 length: %d" % sec5_len
            if expiration_date:
                sec1['blacklist_date']=time.strftime("%a, %d %b %Y %X GMT", time.gmtime(blacklist_timestamp))
            if cert_expiration_date:
                sec1['cert_expiration_date']=time.strftime("%a, %d %b %Y %X GMT", time.gmtime(cert_expiration_date))
    else:
        print "Current file version, %d, is not supported at this time." % cache_ver

    if sec2_len:
        if cache_ver == 602: idx_file['sec2']=sec2_parse_old(data)
        else: idx_file['sec2']=sec2_parse(data)

    if sec3_len:
        #print "\n[*] Section 3 (Jar Manifest) found:" 
        idx_file['sec3']=sec3_parse(data,sec2_len,sec3_len,filesize)

    if sec4_len:
        #print "\n[*] Section 4 (Code Signer) found:"
        idx_file['sec4']=sec4_parse(data,sec2_len,sec3_len,filesize)
                
    if sec5_len:
        print "\n[*] Section 5 found (offset 0x%X, length %d bytes)" % (128 + sec2_len + sec3_len + sec4_len, sec5_len)
    
    return idx_file

def parse_dl(fname):
    try:
        filetype=magic.from_file(fname)
        filecontent=open(fname,'rb').read()
        (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(fname)
        dl_file={'filename':fname, 'mimetype':filetype,'size':size,'atime':time.strftime("%a, %d %b %Y %X GMT", time.gmtime(atime)),'ctime':time.strftime("%a, %d %b %Y %X GMT", time.gmtime(ctime)),'mtime':time.strftime("%a, %d %b %Y %X GMT", time.gmtime(mtime))}
        if filetype=='HTML document, ASCII text, with CRLF line terminators' or filetype=='XML document text':
            dl_file['jar_href']=re.findall(r'\<jar\ href\=\"(.*?)\"',filecontent)[0]
            main_class_arr=re.findall('\<applet\-desc.*main\-class\=\"(.*?)\"',filecontent)
            if main_class_arr:
                dl_file['main_class']=main_class_arr[0]
            dl_file['parameters']={}
            for param,value in re.findall(r'<param name="(.*?)" value="(.*?)"',filecontent):
                dl_file['parameters'][param]=value
            
        m = hashlib.md5()
        m.update(filecontent)
        dl_file['md5']=m.digest().encode('hex')
    
        # computing sha1
        s = hashlib.sha1()               
        s.update(filecontent)
        dl_file['sha1']=s.digest().encode('hex')
    
        # computing ssdeep
        dl_file['ssdeep']=pydeep.hash_buf(filecontent)
        return dl_file
    except:
        print "Unable to stat the downloaded file"

def print_results(idx,dl):
    """ printing the results for the search"""
    if 'sec2' in idx.keys():
        print 'Download link: '+idx['sec2']['data_url']+'('+idx['sec2']['data_ip']+')'
    if dl:
        print dl['filename']+' --> '+dl['mimetype']
        if 'jar_href' in dl.keys():
            print "JAR download: "+dl['jar_href']
            print "JAR main Class: "+dl['main_class']
            print "JAR Parameters:"
            for param, value in dl['parameters'].items():
                print param+'-->'+value


##########################################################
#    Start __main__()
##########################################################    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Java IDX Parser -- version %s -- by @bbaskin  with contributions from Paul PC'  % __VERSION__)
    parser.add_argument('-f', metavar='F', type=str, help='the base folder for the search')
    
    args=parser.parse_args()
    if args.f and os.path.isdir(args.f):
        dirpath=args.f
    elif args.f and not os.path.isdir(args.f):
        parser.print_help()
        sys.exit()
    else:
        dirpath='.'
    # parsing the whole folder
    for currentdir,listofdirs,listoffiles in os.walk(dirpath):
        if "Java" in currentdir or "6.0" in currentdir:
            for filename in listoffiles:
                if filename[-3:] == "idx":
                    fname=currentdir+'/'+filename
                    print "\n\n"+"="*10+fname+"="*10
                    idx=parse_idx(fname)
                    
                    # looking for the files that the idx downloaded in the folder:
                    dl=parse_dl(fname[:-4])
                    
                    print_results(idx,dl)
            ### End __main__()
