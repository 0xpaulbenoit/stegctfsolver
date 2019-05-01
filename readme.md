# Steg CTF Solver

Steganogrpahy challenges in Capture the Flag competitions are often unoriginal. Creators use the same techniques that they have seen in previous CTFs. It can take a lot of time for a competitor to go through the most common solving techniques manually, but with this tool you can do it in one command.


## How to Run
You can either download the dependencies yourself or use a premade docker container. I suggest using the docker container.
 1. Download https://github.com/DominicBreuker/stego-toolkit
 2. Run with `docker run -it --rm -v $(pwd)/data:/data dominicbreuker/stego-toolkit /bin/bash`
 3. Copy this repo into `data`, the folder shared with the container
 4. Run `pip install -r requirements.txt` in the container
 5. Run `apt-get install xxd` in the container
 6. Drag the files you want to analyze into the `data` folder
 7. Run `python3 stegctfsolver.py <target file>`
 
## What it does
It solves the following types of challenges:
 - Flag in strings (searches for anything with ctf{} or flag{}. Optional -f switch to supply your own flag format)
 - Prints GPS coordinates
 - Filecarving with binwalk and foremost
 - PNGs with the bytes reversed
 - PNGs with a corrupted or missing header
 - Extracts frames from GIFs
 - Makes multiple spectrograms from MP3 or WAV files
 - Brute forces LSB Steg

It also runs the following tools:
|  Tool  | Command |
|----------------|--------------------------|
| binwalk  | `binwalk -e <target file>`  |
| foremost| `foremost <target file>` |
| stegdetect| `stegdetect <target file>` |
| stegoveritas.py| `stegoveritas.py <target file>` |
| zsteg| `zsteg -a <target file>` |
| pngcheck| `pngcheck -v <target file>` |
| hideme | `hideme <target file> -f`|
|ffmpeg | `ffmpeg -i <target file> -lavfi showspectrumpic <outfile>`|
|ffmpeg | `ffmpeg -i <target file> -vf scale=5000:500 <outfile>`|