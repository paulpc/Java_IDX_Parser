# Java Cache IDX parser
# Version 0.1 - 12 Jan 13 - @bbaskin
# Views cached Java download history files
# Typically located in %AppData%\LocalLow\Sun\Java\Deployment\Cache
# These files hold critical details for malware infections, especially
# Java related ones, e.g. BlackHole.

## This is very quick and ugly code, not very pythonistic
## I struggle with Python's lack of a 'struct', so just did this manually
import sys
import struct
	
print "Java IDX Parser -- version 1.0 -- by @bbaskin"
print ""

try:
	fname = sys.argv[1]
except:
	print "Usage: idx_parser.py <filename>"
	quit()
	
try:	
	data = open(fname, 'rb').read()
except:
	print "File not found: %s" % fname
	quit()
	
header = data[0:8].encode("hex")
if header != "00000000025d0000":
	print "Invalid IDX header found"
	print "Found:    0x%s" % header
	print "Expected: 0x00000000025d0000"
	quit()

offset = data.find('http') - 1
if offset < 0:
	print "HTTP URL not found!"
	quit()
len_URL = ord(data[offset])+1
data_URL = data[offset+1:offset+len_URL]

#This is ugly, sorry. I should likely have done it with 
#dictionary or list appends.

offset += len_URL
len_IP = struct.unpack(">l", data[offset:offset+4])[0]
offset += 4
data_IP = data[offset:offset+len_IP]
offset += len_IP
data_unk1 = struct.unpack(">l", data[offset:offset+4])[0]
offset += 4

len_unk2 = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_unk2 = data[offset:offset+len_unk2]
offset += len_unk2

len_httpstatus = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_httpstatus = data[offset:offset+len_httpstatus]
offset += len_httpstatus

len_contentlenhdr = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_contentlenhdr = data[offset:offset+len_contentlenhdr]
offset += len_contentlenhdr

len_contentlen = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_contentlen = data[offset:offset+len_contentlen]
offset += len_contentlen

len_modifiedhdr = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_modifiedhdr = data[offset:offset+len_modifiedhdr]
offset += len_modifiedhdr

len_modified = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_modified = data[offset:offset+len_modified]
offset += len_modified

len_typehdr = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_typehdr = data[offset:offset+len_typehdr]
offset += len_typehdr

len_type = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_type = data[offset:offset+len_type]
offset += len_type

len_datehdr = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_datehdr = data[offset:offset+len_datehdr]
offset += len_datehdr

len_date = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_date = data[offset:offset+len_date]
offset += len_date

len_serverhdr = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_serverhdr = data[offset:offset+len_serverhdr]
offset += len_serverhdr

len_server = struct.unpack(">h", data[offset:offset+2])[0]
offset += 2
data_server = data[offset:offset+len_server]
offset += len_server

# Print results
print "IDX file: %s" % fname
print "URL : %s" % (data_URL)
print "IP : %s" % (data_IP)
print "JAR Size : %s" % (data_contentlen)
print "Type : %s" % (data_type)
print "Server Date : %s" % (data_modified)
print "Server type : %s" % (data_server)
print "Download date : %s" % (data_date)
