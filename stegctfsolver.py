#Automaticlally tries to solve steganography CTF challenges
from termcolor import colored
import magic
import argparse
import re
import string,sys,os,io,shutil
import base64
import binascii
from GPSPhoto import gpsphoto
import subprocess
import tempfile

#command line args
parser = argparse.ArgumentParser()
parser.add_argument('file', nargs='?', help='file to analyze')
parser.add_argument('-f', '--format', help='custom regex for flag format', nargs='?')
#parser.add_argument('-p', '--password', help='password if you think one was used', nargs='?')
args = parser.parse_args()

def main():
    filetype = getfiletype(args.file)
    print(filetype)

    cwd = os.getcwd()
    f = args.file.split('/')[-1]
    outputdir = cwd + '/%s-stegresults' % f

    if os.path.isdir(outputdir):
        print('%s already exists' % outputdir)
        exit()
    os.mkdir(outputdir)

    for s in strings(args.file):
        if search(s):
            print(colored(s, 'red'))

    exifdata = exif(args.file)
    if exifdata:
        print('GPS Coordinates Found')
        print('Latitude: ', exifdata['Latitude'])
        print('Longitude: ', exifdata['Longitude'])

    binwalk(args.file, outputdir)
    foremost(args.file, outputdir)

    if filetype.startswith('JPEG') or filetype.startswith('JPG'):
        stegdetect(args.file)
        stegoveritas(args.file, outputdir)

    if filetype.startswith('PC bitmap'):
        stegoveritas(args.file, outputdir)
        zsteg(args.file)

    if filetype.startswith('GIF'):
        stegoveritas(args.file, outputdir)
        extractframes(args.file, outputdir)

    if filetype.startswith('MPEG ADTS') or filetype.startswith('RIFF'):
        spectrogram(args.file, outputdir)
        hideme(args.file)

    #extension
    if args.file.endswith('.png'):
        #attempting to fix invalid header
        #TODO make this output to a directory
        if filetype == 'data':
            print('This is not a valid png')

            f = open(args.file, 'rb')
            content = f.read()
            contentnoheader = f.read(7)

            header = bytes([137,80,78,71,13,10,26,10])
            with open('%s/headerfix1.png' % outputdir,'wb') as outfile:
                outfile.write(header)
                outfile.write(content)

            with open('%s/headerfix2.png' % outputdir,'wb') as outfile:
                outfile.write(header)
                outfile.write(contentnoheader)
            f.close()


        zsteg(args.file)
        stegoveritas(args.file, outputdir)
        pngcheck(args.file, outputdir)


#determine file type
def getfiletype(filename):
    ftype = magic.from_file(filename)
    return ftype

#taken directly from https://stackoverflow.com/questions/17195924/python-equivalent-of-unix-strings-utility
def strings(filename, min=7):
    with open(filename, errors='ignore') as f:
        result = ''
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ''
        if len(result) >= min:  # catch result at EOF
            yield result


#search string for flag
def search(s):
    regex = 'flag{.*}|(ctf|CTF){.*}'
    if args.format:
        regex += '|%s' % args.format
    flag = re.search(regex, s)
    if flag:
        return True
    else:
        return False

#exif data
def exif(filename):
    data = gpsphoto.getGPSData(filename)
    if ('Latitude' in data.keys()) and ('Longitude' in data.keys()):
        return data
    else:
        return False

#binwalk -e
def binwalk(filename, outputdir):
    output = subprocess.run(['binwalk', '-e', '--directory=%s' % outputdir, filename], stdout=subprocess.PIPE).stdout.decode('utf-8')
    print(output)

#foremost
def foremost(filename, outputdir):
    outdir = '%s/foremost' % outputdir
    subprocess.run(['foremost', '-o', outdir, filename], stdout=subprocess.PIPE)

#stegdetect
def stegdetect(filename):
    output = subprocess.run(['stegdetect', filename], stdout=subprocess.PIPE).stdout.decode('utf-8')
    print(output)

#stegoveritas.py
def stegoveritas(filename, outputdir):
    outdir = outputdir + '/stegoveritas'
    os.mkdir(outdir)
    print('brute forcing LSB with stegoveritas')
    print('this may take a minute')
    output = subprocess.run(['stegoveritas.py', filename], stdout=subprocess.PIPE).stdout.decode('utf-8')
    for line in output.split(os.linesep):
        if search(line):
            print(colored(line, 'red'))
    shutil.move('results',outdir)

    trailingfile = '%s/results/trailing_data.bin' % outdir
    if os.path.isfile(trailingfile):
        print('FOUND TRAILING DATA')
        print(getfiletype(trailingfile))
        #TODO try to uncompress file and read/strings it

#zsteg -a
def zsteg(filename):
    print('brute forcing LSB with zsteg')
    output = subprocess.run(['zsteg', '-a', filename], stdout=subprocess.PIPE).stdout.decode('utf-8')
    print(output)
    for line in output.split(os.linesep):
        if search(line):
            print(colored(line, 'red'))

#pngcheck
def pngcheck(filename, outputdir):
    #auto fix header
    f = open(filename, 'rb')

    #extract illegal chunk
    p = subprocess.Popen(['pngcheck', '-v', filename], stdout=subprocess.PIPE)
    for line in io.TextIOWrapper(p.stdout, encoding="utf-8"):
        print(str(line))
        if 'illegal (unless recently approved) unknown, public chunk' in line:
            m = re.search('offset 0x([0-9]*[a-z]*), length ([0-9]*)', line)
            if m:
                print('writing content of illegal chunk to chunk.bin')
                f = open(filename, 'rb')
                offset = int(m.group(1), 16)
                length = int(m.group(2))
                f.seek(offset, 1)
                chunk = f.read(length)
                filechunk = open('%s/chunk.bin' % outputdir, 'wb')
                filechunk.write(chunk)
                f.close()

    #flip file bytes
    reversefile = open(outputdir + '/reversed.png', 'w')
    p1 = subprocess.Popen(['xxd', '-p', '-c1', args.file], stdout=subprocess.PIPE,)
    p2 = subprocess.Popen(['tac'], stdin=p1.stdout,  stdout=subprocess.PIPE)
    p3 = subprocess.Popen(['xxd', '-p', '-r'], stdin=p2.stdout,  stdout=reversefile)


#ffmpeg audio convert waveform and save spectrogram as image in different ratios
def spectrogram(filename, outputdir):
    outfile1 = '%s/spectrum1.png' % outputdir
    outfile2 = '%s/spectrum2.png' % outputdir
    subprocess.run(['ffmpeg', '-i', filename, '-lavfi', 'showspectrumpic', outfile1], stdout=subprocess.PIPE)
    subprocess.run(['ffmpeg', '-i', outfile1, '-vf', 'scale=5000:500', outfile2], stdout=subprocess.PIPE)

def hideme(filename):
    output = subprocess.run(['hideme', filename, '-f'], stdout=subprocess.PIPE).stdout
    print(output)

def extractframes(filename, outputdir):
    print('Extracting GIF frames')
    outfile = '%s/frame%%03d.png' % outputdir
    output = subprocess.run(['ffmpeg', '-i', filename, '-vsync', '0', outfile], stdout=subprocess.PIPE).stdout
    #ffmpeg -i path/to/gif -vsync 0 path/to/output$03d.png

if __name__ == '__main__':
    main()