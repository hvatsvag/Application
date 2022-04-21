#import stix2viz
from datetime import datetime
from itertools import count
from stix2elevator import elevate, stix_stepper
from stix2elevator.options import initialize_options, set_option_value, get_validator_options
import json
import spacy
from spacy.matcher import Matcher
import asyncio


def try_elevate_options(list):

    #print("\n\n", len(list), "\n\n")
    list_elevated = []
    rest_list = []
    for i in list:
        try:
                
            json_info = elevate(i[0])
            list_elevated.append([json_info, i[1]])
            #print(f"\n\n\n\n The important stuff {json_info} \n\n\n\n")
                #print("Found the important text")
                
        except:
            rest_list.append(i)
            pass
    return list_elevated, rest_list



async def find_relevant_spacy_list(list_of_stuff):
    #print(len(list_of_stuff))
    
    nlp = spacy.load("en_core_web_sm")
    ruler = nlp.add_pipe("entity_ruler", before="ner")
    transport_protocol = ["tcp", "TCP", "icmp", "ICMP", "udp", "UDP"]
    patterns_ruler = [
        {"label": "transport", "pattern": protocol} for protocol in transport_protocol
    ]

    ruler.add_patterns(patterns_ruler)

    all_entries = []
    list_of_elevated_stuff = []
    rest_list = []
    #elevate_options = ['"spec_version": "2.0"', '"spec_version": "2.1"', '"spec_version": "2.1.1"', '"spec_version": "1.0"', '"spec_version": "1.1"', '"spec_version": "1.1.1"']
    #elevator_setup = initialize_options(options={"spec_version": "2.0"})


    
    octet_rx = r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    patterns_matcher = [{"TEXT": {"REGEX": r"^{0}(?:\.{0}){{3}}$".format(octet_rx)}},]
    patterns_matcher2 = [
        {"TEXT": "MD5"},
        {"TEXT": ":"},
        #{"TEXT": {"REGEX": r"^[0-9a-fA-F]{32}$"}},
        {"IS_ASCII": True}
        #{"ORTH": ","}
    ]
    patterns_matcher3 = [
        {"TEXT": "SHA-256"},
        {"TEXT": ":"},
        {"ORTH": "None", "OP": "!"},
        {"IS_ASCII": True}
        #{"ORTH": "."}
    ]

    #patterns_matcher4 = [
    #    {"LIKE_URL": True, "OP": "+"},
        #{"ORTH": "http://vxvault", "OP": "!"}
    #    ]
    patterns_matcher5 = [
        {"TEXT": {"REGEX": r"^{0}(?:\.{0}){{3}}$".format(octet_rx)}},
        {"TEXT": ":", "OP": "?"},
        {"TEXT": {"REGEX": r"[0-9]{2}?"}, "OP": "+"}
    ]
    patterns_matcher6 = [
        {"TEXT": "Port"},
        {"TEXT": {"REGEX": r"[0-9]{2}?"}, "OP": "+"}
    ]
    patterns_matcher7 = [
        {"TEXT": "Ports"},
        {"TEXT": ":"},
        {"TEXT": "{"},
        {"IS_ASCII": True, "OP": "+"},
        {"TEXT": "}"}
    ]
    
    matcher = Matcher(nlp.vocab)
    matcher.add("ipv4", [patterns_matcher])
    matcher.add("MD5", [patterns_matcher2])
    matcher.add("SHA-256", [patterns_matcher3])
    #matcher.add("URL", [patterns_matcher4])
    matcher.add("ipv4 and port", [patterns_matcher5])
    matcher.add("Port", [patterns_matcher6])
    matcher.add("Ports", [patterns_matcher7])
    
    
    initialize_options(options={"silent": True})

    counter = 0
    for i in list_of_stuff:        
                    

        relevant_info = ""
        if i[0] != None:
            relevant_info = i[0]
            '''
            relevant_info = json.loads(i[0])
            
            print(info)
            try:
                relevant_info = info["description"]
            except KeyError as err:
                print(err)
                continue
            '''
            

        relevant_info = relevant_info.replace("'", " ' ")
        relevant_info = relevant_info.replace('"', ' " ')
        relevant_info = relevant_info.replace("[", "[ ")
        relevant_info = relevant_info.replace("]", " ]")
        relevant_info = relevant_info.replace(",", " , ")
        relevant_info = relevant_info.replace(":", " : ")
        relevant_info = relevant_info.replace("(", "() ")
        relevant_info = relevant_info.replace(")", " )")

        doc = nlp(relevant_info)
        matches = matcher(doc)
        new_matches = []
        #print("Len og matches is", len(matches))
        if len(matches) > 0:
            span_list = []
            for match_id, start, end in matches:
                
                str_id = nlp.vocab.strings[match_id]
                span = doc[start:end]
                #if span in span_list:
                #    continue
                span_list.append(span)
                print("This is the matches", match_id, str_id, start, end, span.text)
                new_matches.append([f"{str_id}", f"{span.text}"])
            #print("Added to ruler")
            #entrys = nlp(relevant_info)
        #all_entries.append([entrys, i[1]], new_matches)
        #print("The lengt of all entrys is", len(all_entries), "Added", [doc, i[1]], new_matches)
        all_entries.append([doc, i[1], new_matches])
        #print("The lengt of all entrys is", len(all_entries), "Added", [entrys, i[1]])
        counter += 1
        if counter % 100 == 0:
            print("Elevated documents processed by spacy", counter)
   
    return all_entries

# This one does not convert stix to json
async def find_relevant_spacy_stix(list_of_stuff):
    #print(len(list_of_stuff))
    #nlp = spacy.load("en_core_web_sm")
    nlp = spacy.blank("en")
    #ruler = nlp.add_pipe("entity_ruler", before="ner")
    ruler = nlp.add_pipe("entity_ruler")
    transport_protocol = ["tcp", "TCP", "icmp", "ICMP", "udp", "UDP"]
    patterns_ruler = [
        {"label": "transport", "pattern": protocol} for protocol in transport_protocol
    ]

    ruler.add_patterns(patterns_ruler)
    all_entries = []
    all_maches = []
    #list_of_elevated_stuff = []
    #rest_list = []
    
    
    octet_rx = r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    patterns_matcher = [{"TEXT": {"REGEX": r"^{0}(?:\.{0}){{3}}$".format(octet_rx)}},]
    patterns_matcher2 = [{"TEXT": "MD5"}, {"TEXT": ":"}, {"IS_ASCII": True}]
    patterns_matcher3 = [{"TEXT": "SHA-256"}, {"TEXT": ":"}, {"TEXT": "None", "OP": "!"}, {"IS_ASCII": True}]
    #patterns_matcher4 = [{"LIKE_URL": True}]
    patterns_matcher4 = [
        {"TEXT": "SHA256"},
        {"TEXT": "-", "OP": "?"},
        {"TEXT": "None", "OP": "!"},
        {"IS_ASCII": True}
        #{"ORTH": "."}
    ]
    patterns_matcher5 = [{"TEXT": {"REGEX": r"^{0}(?:\.{0}){{3}}$".format(octet_rx)}}, {"TEXT": ":", "OP": "?"}, {"TEXT": {"REGEX": r"[0-9]{2}?"}, "OP": "+"}]
    patterns_matcher6 = [{"TEXT": "Port"}, {"TEXT": {"REGEX": r"[0-9]{2}?"}, "OP": "+"}]
    patterns_matcher7 = [
        {"TEXT": "Ports"}, 
        {"TEXT": ":"}, 
        {"TEXT": "{"}, 
        {"IS_ASCII": True, "OP": "+"}, 
        {"TEXT": "}"}
        ]
    patterns_matcher8 = [{"TEXT": "port"}, {"TEXT": {"REGEX": r"[0-9]{2}?"}, "OP": "+"}]
    matcher = Matcher(nlp.vocab)
    matcher.add("ipv4", [patterns_matcher])
    matcher.add("MD5", [patterns_matcher2])
    matcher.add("SHA-256", [patterns_matcher3])
    #matcher.add("URL", [patterns_matcher4])
    matcher.add("SHA256", [patterns_matcher4])
    matcher.add("ipv4 and port", [patterns_matcher5])
    matcher.add("Port", [patterns_matcher6])
    matcher.add("Ports", [patterns_matcher7])
    matcher.add("port", [patterns_matcher8])
    
    counter = 0 
    
    for i in list_of_stuff:
        try:
            #print("Running one file trough spacy", datetime.now())
            #print(type(i[0]))
            #print(i[0])
            information = str(i[0].decode())
            information = information.replace("'", " ' ")
            information = information.replace("[", "[ ")
            information = information.replace("]", " ]")
            information = information.replace("(", "( ")
            information = information.replace(")", " )")
            information = information.replace(",", " , ")
            information = information.replace("<", " <")
            information = information.replace(">", "> ")
            information = information.replace(":", " : ")
            doc = nlp(information)
            new_matches = []
            matches = matcher(doc)
            #print("Len og matches is", len(matches))
                
            span_list = []
            for match_id, start, end in matches:
                    
                str_id = nlp.vocab.strings[match_id]
                span = doc[start:end]
                if span in span_list:
                    continue
                span_list.append(span)
                #print("This is the matches", match_id, str_id, start, end, span.text)
                new_matches.append([f"{str_id}", f"{span.text}"])
                
            
                #ruler.add_patterns(new_patterns_ruler)
                #print("Added to ruler")
                #entrys = nlp(information)
            all_entries.append([doc, i[1], new_matches])
            #print("The lengt of all entrys is", len(all_entries), "Added", [entrys, i[1]])
            counter += 1
            if counter % 100 == 0:
                print("STIX documents processed by spacy", counter)
            if counter % 6 == 0:
                await asyncio.sleep(0.00000001)
            #print("Done running one file trough spacy", datetime.now())
        except:
            
            pass
    return all_entries#, rest_list


'''
def find_relevant_spacy_list_failed(list_of_stuff):
    initialize_options(options={"spec_version": "2.0"})
    nlp = spacy.load("en_core_web_sm")
    all_entries = []
    #delete_list = []
    
    ruler = nlp.add_pipe("entity_ruler", before="ner")
    octet_rx = r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    patterns_matcher = [{"TEXT": {"REGEX": r"^{0}(?:\.{0}){{3}}$".format(octet_rx)}},]
    patterns_matcher2 = [
        {"ORTH": "MD5"},
        {"ORTH": ":"},
        #{"TEXT": {"REGEX": r"^[0-9a-fA-F]{32}$"}},
        {"IS_ASCII": True}
        #{"ORTH": ","}
    ]
    patterns_matcher3 = [
        {"ORTH": "SHA-256"},
        {"ORTH": ":"},
        {"ORTH": "None", "OP": "!"},
        {"IS_ASCII": True}
        #{"ORTH": "."}
    ]

    patterns_matcher4 = [
        {"LIKE_URL": True},
        #{"ORTH": "http://vxvault", "OP": "!"}
        ]
    matcher = Matcher(nlp.vocab)
    matcher.add("ipv4", [patterns_matcher])
    matcher.add("MD5", [patterns_matcher2])
    matcher.add("SHA-256", [patterns_matcher3])
    matcher.add("URL", [patterns_matcher4])

    for i in list_of_stuff:
        text = i[0]
        json_info = None
        try:
            json_info = elevate(text)
        except:
            #delete_list.append(i[1])
            print(f"Excepted {i[1]}")
        #json_info = elevate(text)
        relevant_info = ""
        if json_info != None:
            json_info = json.loads(json_info)

            

            # Finding relevant info
            for key, value in json_info.items():
                if key == "objects":
                    value = json.loads(json.dumps(value))
                    for k in value:
                        #print(k, type(k))
                        if "description" in k:
                            
                            relevant_info += k["description"] + "\n"
                        if "definition" in k and "statement" in k["definition"]:
                            
                            #for m in k["definition"]:
                            relevant_info += k["definition"]["statement"] + "\n"
        
        # Use relevant info

        entrys = nlp(relevant_info)
        matches = matcher(entrys)
        if len(matches) > 0:
            patterns_ruler = []
            for match_id, start, end in matches:
                str_id = nlp.vocab.strings[match_id]
                span = entrys[start:end]
                #print(match_id, str_id, start, end, span.text)
                patterns_ruler.append({"label": f"{str_id}", "pattern": f"{span.text}"})
            
            ruler.add_patterns(patterns_ruler)
            entrys = nlp(relevant_info)
        all_entries.append([entrys, i[1]])

    return all_entries, #delete_list

'''


def find_relevant_info(info):
    #print(info)
    initialize_options(options={"spec_version": "2.1.1"})
    #info = info.lstrip(" b'")
    try:
        json_info = elevate(info)
    except:
        return None
    #print(json_info)
    json_info = json.loads(json_info)
    #print(json_info)
    #print(type(json_info))
    relevant_info = ""
    for key, value in json_info.items():
        if key == "objects":
            #print(type(value[0]))
            #print("The whole value is ", value)
            #print(value[0])
            value = json.loads(json.dumps(value))
            print(value)
            #value_json = json.loads(value[0])
            for k in value:
                #print(k, type(k))
                if "description" in k:
                    #print("This is relevant", k["description"])
                    relevant_info += k["description"] + "\n"
                if "definition" in k and "statement" in k["definition"]:
                    #print("This is relevant", k["definition"]["statement"])
                    #for m in k["definition"]:
                    relevant_info += k["definition"]["statement"] + "\n"
                #print("added info")
            '''
            for key2, v in value_json:
                print(type(v))
                relevant_info += v + "\n"
#            for key2, value2 in value:
#                if key2 == "description":
#                    relevant_info += value2 + "\n"
            '''
    #print('Relevant info er ' + relevant_info)
    #print("This is the json string", json_info)
    return relevant_info

def find_relevant_spacy(info):
    #info = info.replace(",", " ,")
    #info = info.replace(".", " .")
    #print("Relevant info is", info)
    patterns_ruler = []
    octet_rx = r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    patterns_matcher = [{"TEXT": {"REGEX": r"^{0}(?:\.{0}){{3}}$".format(octet_rx)}},]
    patterns_matcher2 = [
        {"ORTH": "MD5"},
        {"ORTH": ":"},
        #{"TEXT": {"REGEX": r"^[0-9a-fA-F]{32}$"}},
        {"IS_ASCII": True}
        #{"ORTH": ","}
    ]
    patterns_matcher3 = [
        {"ORTH": "SHA-256"},
        {"ORTH": ":"},
        {"ORTH": "None", "OP": "!"},
        {"IS_ASCII": True}
        #{"ORTH": "."}
    ]

    #patterns_matcher4 = [
    #    {"LIKE_URL": True},
        #{"ORTH": "http://vxvault", "OP": "!"}
    #    ]

    
    
    nlp = spacy.load("en_core_web_sm")
    entrys = nlp(info)
    matcher = Matcher(nlp.vocab)
    matcher.add("ipv4", [patterns_matcher])
    matcher.add("MD5", [patterns_matcher2])
    matcher.add("SHA-256", [patterns_matcher3])
    #matcher.add("URL", [patterns_matcher4])
    matches = matcher(entrys)
    if len(matches) > 0:
        for match_id, start, end in matches:
            str_id = nlp.vocab.strings[match_id]
            span = entrys[start:end]
            #print(match_id, str_id, start, end, span.text)
            patterns_ruler.append({"label": f"{str_id}", "pattern": f"{span.text}"})
        ruler = nlp.add_pipe("entity_ruler", before="ner")
        ruler.add_patterns(patterns_ruler)
        entrys = nlp(info)
    return entrys

if __name__ == '__main__':
    info =[['''
    <stix:STIX_Package xmlns:cyboxCommon="http://cybox.mitre.org/common-2" xmlns:cybox="http://cybox.mitre.org/cybox-2" xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2" xmlns:marking="http://data-marking.mitre.org/Marking-1" xmlns:simpleMarking="http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1" xmlns:tlpMarking="http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1" xmlns:TOUMarking="http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1" xmlns:opensource="http://hailataxii.com" xmlns:edge="http://soltra.com/" xmlns:indicator="http://stix.mitre.org/Indicator-2" xmlns:stixCommon="http://stix.mitre.org/common-1" xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1" xmlns:stix="http://stix.mitre.org/stix-1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:taxii="http://taxii.mitre.org/messages/taxii_xml_binding-1" xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" xmlns:tdq="http://taxii.mitre.org/query/taxii_default_query-1" id="edge:Package-d161d6b5-71be-4c08-87d9-4d85dabacc9f" version="1.1.1" timestamp="2022-02-16T09:48:43.130938+00:00">
    <stix:STIX_Header>
        <stix:Handling>
            <marking:Marking>
                <marking:Controlled_Structure>../../../../descendant-or-self::node()</marking:Controlled_Structure>
                <marking:Marking_Structure xsi:type="tlpMarking:TLPMarkingStructureType" color="WHITE"/>
                <marking:Marking_Structure xsi:type="TOUMarking:TermsOfUseMarkingStructureType">
                    <TOUMarking:Terms_Of_Use>www.dshield.org | https://www.dshield.org - DShield.org Recommended Block List (c) 2007 DShield.org some rights reserved. Details http://creativecommons.org/licenses/by-nc-sa/2.5/ use on your own risk. No warranties implied. primary URL: http://feeds.dshield.org</TOUMarking:Terms_Of_Use>
                </marking:Marking_Structure>
                <marking:Marking_Structure xsi:type="simpleMarking:SimpleMarkingStructureType">
                    <simpleMarking:Statement>Unclassified (Public)</simpleMarking:Statement>
                </marking:Marking_Structure>
            </marking:Marking>
        </stix:Handling>
    </stix:STIX_Header>
    <stix:Indicators>
        <stix:Indicator id="opensource:indicator-04348417-4cb4-4b46-b99e-747deb52995f" timestamp="2015-01-02T14:39:13.160092+00:00" xsi:type="indicator:IndicatorType" version="2.1.1">
            <indicator:Title>212.83.149.0 - 212.83.149.255 | DShield.org Recommended Block List </indicator:Title>
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">IP Watchlist</indicator:Type>
            <indicator:Description>This IP block appears to have originated in FR(France) and is register to abuse@worldonline.fr of 92130 Issy-les-Moulineaux.</indicator:Description>
            <indicator:Observable idref="opensource:Observable-9485c23c-519e-4994-b989-527289a34ec6">
            </indicator:Observable>
            <indicator:Producer>
                <stixCommon:Identity id="opensource:Identity-e7617794-910b-46f6-8589-50c36fdce735">
                    <stixCommon:Name>www.dshield.org</stixCommon:Name>
                </stixCommon:Identity>
                <stixCommon:Time>
                    <cyboxCommon:Produced_Time>2015-01-02T14:26:37+00:00</cyboxCommon:Produced_Time>
                    <cyboxCommon:Received_Time>2015-01-02T14:39:13+00:00</cyboxCommon:Received_Time>
                </stixCommon:Time>
            </indicator:Producer>
        </stix:Indicator>
    </stix:Indicators>
</stix:STIX_Package>
    
    ''', 1
    ], ['''
    <stix:STIX_Package xmlns:cyboxCommon="http://cybox.mitre.org/common-2" xmlns:cybox="http://cybox.mitre.org/cybox-2" xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2" xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2" xmlns:marking="http://data-marking.mitre.org/Marking-1" xmlns:simpleMarking="http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1" xmlns:tlpMarking="http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1" xmlns:TOUMarking="http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1" xmlns:opensource="http://hailataxii.com" xmlns:edge="http://soltra.com/" xmlns:stixCommon="http://stix.mitre.org/common-1" xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1" xmlns:stix="http://stix.mitre.org/stix-1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:taxii="http://taxii.mitre.org/messages/taxii_xml_binding-1" xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" xmlns:tdq="http://taxii.mitre.org/query/taxii_default_query-1" id="edge:Package-6b704315-db10-4de5-980c-f031eeeac575" version="1.1.1" timestamp="2022-02-16T09:50:03.724458+00:00">
    <stix:STIX_Header>
        <stix:Handling>
            <marking:Marking>
                <marking:Controlled_Structure>../../../../descendant-or-self::node()</marking:Controlled_Structure>
                <marking:Marking_Structure xsi:type="tlpMarking:TLPMarkingStructureType" color="WHITE"/>
                <marking:Marking_Structure xsi:type="TOUMarking:TermsOfUseMarkingStructureType">
                    <TOUMarking:Terms_Of_Use>rules.emergingthreats.net | #  Copyright (c) 2003-2014, Emerging Threats
#  All rights reserved.
#  
#  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the 
#  following conditions are met:
#  
#  * Redistributions of source code must retain the above copyright notice, this list of conditions and the following 
#    disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the 
#    following disclaimer in the documentation and/or other materials provided with the distribution.
#  * Neither the name of the nor the names of its contributors may be used to endorse or promote products derived 
#    from this software without specific prior written permission.
#  
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS AND ANY EXPRESS OR IMPLIED WARRANTIES, 
#  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
#  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE 
#  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
</TOUMarking:Terms_Of_Use>
                </marking:Marking_Structure>
                <marking:Marking_Structure xsi:type="simpleMarking:SimpleMarkingStructureType">
                    <simpleMarking:Statement>Unclassified (Public)</simpleMarking:Statement>
                </marking:Marking_Structure>
            </marking:Marking>
        </stix:Handling>
    </stix:STIX_Header>
    <stix:Observables cybox_major_version="2" cybox_minor_version="1" cybox_update_version="0">
        <cybox:Observable id="opensource:Observable-4a995a1e-9d2c-4825-ad9f-de2fd59d1802" sighting_count="1">
            <cybox:Title>IP: 88.198.57.73</cybox:Title>
            <cybox:Description>IPv4: 88.198.57.73 | isDestination: True | </cybox:Description>
            <cybox:Object id="opensource:Address-df0d012c-aaae-4953-ad87-8298d21f5736">
                <cybox:Properties xsi:type="AddressObj:AddressObjectType" category="ipv4-addr" is_destination="true">
                    <AddressObj:Address_Value condition="Equals">88.198.57.73</AddressObj:Address_Value>
                </cybox:Properties>
            </cybox:Object>
        </cybox:Observable>
    </stix:Observables>
</stix:STIX_Package>
    
    ''', 2
    ], ['''
    <stix:STIX_Package xmlns:cyboxCommon="http://cybox.mitre.org/common-2" xmlns:cybox="http://cybox.mitre.org/cybox-2" xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2" xmlns:marking="http://data-marking.mitre.org/Marking-1" xmlns:simpleMarking="http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1" xmlns:tlpMarking="http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1" xmlns:TOUMarking="http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1" xmlns:opensource="http://hailataxii.com" xmlns:edge="http://soltra.com/" xmlns:indicator="http://stix.mitre.org/Indicator-2" xmlns:stixCommon="http://stix.mitre.org/common-1" xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1" xmlns:stix="http://stix.mitre.org/stix-1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:taxii="http://taxii.mitre.org/messages/taxii_xml_binding-1" xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" xmlns:tdq="http://taxii.mitre.org/query/taxii_default_query-1" id="edge:Package-fec03814-98ee-4fe5-ac2c-551bbc40f387" version="1.1.1" timestamp="2022-02-16T09:41:09.405580+00:00">
    <stix:STIX_Header>
        <stix:Handling>
            <marking:Marking>
                <marking:Controlled_Structure>../../../../descendant-or-self::node()</marking:Controlled_Structure>
                <marking:Marking_Structure xsi:type="tlpMarking:TLPMarkingStructureType" color="WHITE"/>
                <marking:Marking_Structure xsi:type="TOUMarking:TermsOfUseMarkingStructureType">
                    <TOUMarking:Terms_Of_Use>torstatus.blutmagie.de | http://torstatus.blutmagie.de - HailATaxii.com (HAT) has made a 'best effort' attempt to find/determined the TOU (Term of Use) for this site's data, however none was found. 

- HAT assumes that attribution is a minimum requirement.
- HAT assumes this data was created and owned by torstatus.blutmagie.de.
- HAT has only modified the format of the data from CSV to STIX, and has not made any changes to the contains of the data as it was received at the time of conversion.
</TOUMarking:Terms_Of_Use>
                </marking:Marking_Structure>
                <marking:Marking_Structure xsi:type="simpleMarking:SimpleMarkingStructureType">
                    <simpleMarking:Statement>Unclassified (Public)</simpleMarking:Statement>
                </marking:Marking_Structure>
            </marking:Marking>
        </stix:Handling>
    </stix:STIX_Header>
    <stix:Indicators>
        <stix:Indicator id="opensource:indicator-1ba90cd5-a34d-469b-9632-1c9abea32cbb" timestamp="2015-01-26T03:05:22.745590+00:00" xsi:type="indicator:IndicatorType" version="2.1.1">
            <indicator:Title> This domain p5DC30AA5.dip0.t-ipconnect.de has been identified as a TOR network "Exit Point" router</indicator:Title>
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">IP Watchlist</indicator:Type>
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Domain Watchlist</indicator:Type>
            <indicator:Description> torstatus.blutmagie.de has identified this domain p5DC30AA5.dip0.t-ipconnect.de as a TOR network "Exit Point" router, which appears to be located in Germany. 

 RawData: {'IP Address': u'93.195.10.165', 'Uptime (Days)': 1, 'Flags': {'Flag - Named': 0, 'Flag - Stable': 0, 'Flag - Bad Exit': 0, 'Flag - Authority': 0, 'Flag - Valid': 1, 'Flag - Guard': 0, 'Flag - Hibernating': 0, 'Flag - Fast': 1, 'Flag - Running': 1, 'Flag - Exit': 0, 'Flag - V2Dir': 1}, 'Country Code': u'DE', 'Platform': u'Tor 0.2.4.23 on Linux', 'Hostname': u'p5DC30AA5.dip0.t-ipconnect.de', 'Ports': {'ORPort': 443, 'DirPort': 9030}, 'Router Name': u'cocotor', 'Bandwidth (KB/s)': 61}</indicator:Description>
            <indicator:Observable idref="opensource:Observable-0d114c48-0d98-4056-b594-a83ed1889749">
            </indicator:Observable>
            <indicator:Producer>
                <stixCommon:Identity id="opensource:Identity-26d6f44f-07b2-4cdd-8e2c-a928d5598d07">
                    <stixCommon:Name>torstatus.blutmagie.de</stixCommon:Name>
                </stixCommon:Identity>
                <stixCommon:Time>
                    <cyboxCommon:Received_Time>2015-01-26T03:05:04+00:00</cyboxCommon:Received_Time>
                </stixCommon:Time>
            </indicator:Producer>
        </stix:Indicator>
    </stix:Indicators>
</stix:STIX_Package>
    
    ''', 3
    ], ['''
    <stix:STIX_Package xmlns:cyboxCommon="http://cybox.mitre.org/common-2" xmlns:cybox="http://cybox.mitre.org/cybox-2" xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2" xmlns:marking="http://data-marking.mitre.org/Marking-1" xmlns:simpleMarking="http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1" xmlns:tlpMarking="http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1" xmlns:TOUMarking="http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1" xmlns:opensource="http://hailataxii.com" xmlns:edge="http://soltra.com/" xmlns:indicator="http://stix.mitre.org/Indicator-2" xmlns:ttp="http://stix.mitre.org/TTP-1" xmlns:stixCommon="http://stix.mitre.org/common-1" xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1" xmlns:stix="http://stix.mitre.org/stix-1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:taxii="http://taxii.mitre.org/messages/taxii_xml_binding-1" xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" xmlns:tdq="http://taxii.mitre.org/query/taxii_default_query-1" id="edge:Package-c369a178-2d91-4c71-bdd6-0bc51bc33337" version="1.1.1" timestamp="2022-02-16T09:33:01.902194+00:00">
    <stix:STIX_Header>
        <stix:Handling>
            <marking:Marking>
                <marking:Controlled_Structure>../../../../descendant-or-self::node()</marking:Controlled_Structure>
                <marking:Marking_Structure xsi:type="tlpMarking:TLPMarkingStructureType" color="WHITE"/>
                <marking:Marking_Structure xsi:type="TOUMarking:TermsOfUseMarkingStructureType">
                    <TOUMarking:Terms_Of_Use>www.malwaredomainlist.com | Malware Domain List - is a non-commercial community project. Our list can be used for free by anyone. Feel free to use it. 
</TOUMarking:Terms_Of_Use>
                </marking:Marking_Structure>
                <marking:Marking_Structure xsi:type="simpleMarking:SimpleMarkingStructureType">
                    <simpleMarking:Statement>Unclassified (Public)</simpleMarking:Statement>
                </marking:Marking_Structure>
            </marking:Marking>
        </stix:Handling>
    </stix:STIX_Header>
    <stix:Indicators>
        <stix:Indicator id="opensource:indicator-be0be73c-325a-484f-8460-222c68de4874" timestamp="2015-01-13T14:57:46.995684+00:00" xsi:type="indicator:IndicatorType" version="2.1.1">
            <indicator:Title>Compromised Site: : otroladolodge.com/taxadmin/get_doc.html</indicator:Title>
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">IP Watchlist</indicator:Type>
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Domain Watchlist</indicator:Type>
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">URL Watchlist</indicator:Type>
            <indicator:Description>This domain otroladolodge.com (50.87.182.107) located in US (United States), has been identified as Malious [Compromised site] by www.malwaredomainlist.com. For more detailed infomation about this indicator go to [CAUTION!!Read-URL-Before-Click] [http://www.malwaredomainlist.com/mdl.php?search=otroladolodge.com].</indicator:Description>
            <indicator:Observable idref="opensource:Observable-06c78a82-5107-4b33-8f69-579672656f54">
            </indicator:Observable>
            <indicator:Indicated_TTP>
                <stixCommon:TTP idref="opensource:ttp-b4b92cb6-0bfc-4777-b6de-85783a93bce6" xsi:type="ttp:TTPType"/>
            </indicator:Indicated_TTP>
            <indicator:Producer>
                <stixCommon:Identity id="opensource:Identity-23130ce4-efcd-480c-b2cd-5c2d3745074a">
                    <stixCommon:Name>www.malwaredomainlist.com</stixCommon:Name>
                </stixCommon:Identity>
                <stixCommon:Time>
                    <cyboxCommon:Produced_Time>2015-01-13T14:47:00+00:00</cyboxCommon:Produced_Time>
                    <cyboxCommon:Received_Time>2015-01-13T14:57:46+00:00</cyboxCommon:Received_Time>
                </stixCommon:Time>
            </indicator:Producer>
        </stix:Indicator>
    </stix:Indicators>
</stix:STIX_Package>
    
    ''', 4
    ]]
    entrys, other = find_relevant_spacy_list(info)
    print(len(other))
    #entrys = find_relevant_spacy(text_description)
    for ent in entrys:
        #spacy_info = ent.text, ent.label_
        print(ent)