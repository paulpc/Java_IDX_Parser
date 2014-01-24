## Java_IDX_Parser

Modified version of Brian Baskin's ids parser. This will go throught the children of the current folder and will look for idx file, then parse them.

Original comments:

The original, and the best, Java Cache IDX parser.

This was written as a result of working quite a few Java malware infection cases. While I grew proficient at manually carving the Java IDX file, which retains download history of malicious Java archives, I learned that a tool may work better when teaching my coworkers how to do the same.

Java IDX files contain high-fidelity indicators about where a piece of malware originated from and how it got onto the infected system. Additionally, most analysis to this point was performed off the text-strings within the file, while ignoring the large blocks of binary data.

At the time of development, there was only one source available for this file, Corey Harrell's blog post from 2011 (http://journeyintoir.blogspot.com/2010/10/anatomy-of-drive-by-part-2.html) and a IDX to Timeline parser written by Sploit (http://sploited.blogspot.com/2012/08/java-forensics-using-tln-timelines.html).

The large blocks of binary data kept bugging me, so I wrote this tool. The initial release did just the basic text sections while I gathered the amount of interest in it. The latest releases perform decompression and basic binary analysis of Java serialization code. At first I used an existing Java serialization module, until I found that Oracle didn't follow their own file specifications, which broke the existing parsers, and required me to write my own.

The latest release removes all interpretation of the file, outputting just raw data to the screen. That way you get a more accurate portrayal of the data, and you can choose what data is relevant to your cause. Even though most Section 4 data appears to be junk to me, it's in there, and its relevance may come to light one day.


## Copyright and license

Copyright 2013 Brian Baskin

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this work except in compliance with the License.
You may obtain a copy of the License in the LICENSE file, or at:

  [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
