import pefile
import os
import subprocess

for file in os.listdir('files'):
	try:
		path = 'files/{}'.format(file)
		
		pe = pefile.PE(path)
		p  = subprocess.Popen([path], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
		
		output = p.communicate(input=''.join(pe.get_data(0x2AB0, 32).split('\x00')))[0]
		
		print output
	except:
		pass