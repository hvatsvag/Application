#import stix2viz
from stix2elevator import elevate
from stix2elevator.options import initialize_options, set_option_value
import json
import spacy
from spacy.matcher import Matcher



def find_relevant_spacy_list(list_of_stuff):
    print(len(list_of_stuff))
    initialize_options(options={"spec_version": "2.0"})
    nlp = spacy.load("en_core_web_sm")
    all_entries = []
    list_of_elevated_stuff = []
    rest_list = []
    
    
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
        #print("The ID is", i[1])
        text = i[0]
        json_info = None
        try:
            json_info = elevate(text)
            list_of_elevated_stuff.append([json_info, i[1]])
            #print("Found the important text")
            #print(f"\n\n\n\n The important stuff {json_info} \n\n\n\n")
        except:
            rest_list.append(i)

    if len(rest_list) > 0:
        new_rest_list = []
        initialize_options(options={"spec_version": "2.1.1"})
        for i in rest_list:
            try:
                
                json_info = elevate(i[0])
                list_of_elevated_stuff.append([json_info, i[1]])
                #print(f"\n\n\n\n The important stuff {json_info} \n\n\n\n")
                #print("Found the important text")
            except:
                new_rest_list.append(i)
                pass
        rest_list = new_rest_list
    if len(rest_list) > 0:
        new_rest_list = []
        initialize_options(options={"spec_version": "1.1.1"})
        for i in rest_list:
            try:
                
                json_info = elevate(i[0])
                list_of_elevated_stuff.append([json_info, i[1]])
                #print(f"\n\n\n\n The important stuff {json_info} \n\n\n\n")
                #print("Found the important text")
            except:
                new_rest_list.append(i)
                pass
        rest_list = new_rest_list
    if len(rest_list) > 0:
        new_rest_list = []
        initialize_options(options={"spec_version": "1.0"})
        for i in rest_list:
            try:
                
                json_info = elevate(i[0])
                list_of_elevated_stuff.append([json_info, i[1]])
                #print(f"\n\n\n\n The important stuff {json_info} \n\n\n\n")
                #print("Found the important text")
            except:
                new_rest_list.append(i)
                pass
        rest_list = new_rest_list
    if len(rest_list) > 0:
        new_rest_list = []
        initialize_options(options={"spec_version": "1.1"})
        for i in rest_list:
            try:
                
                json_info = elevate(i[0])
                list_of_elevated_stuff.append([json_info, i[1]])
                #print(f"\n\n\n\n The important stuff {json_info} \n\n\n\n")
                #print("Found the important text")
            except:
                new_rest_list.append(i)
                pass
        rest_list = new_rest_list   
    counter = 0 
    for i in list_of_elevated_stuff:        
                    
        #print(f"Excepted {i[1]}")
        #json_info = elevate(text)
        relevant_info = ""
        if i[0] != None:
            json_info = json.loads(i[0])

            

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
                        if "objects" in k:
                            #print(k["objects"])
                            
                            for val_type in k["objects"]:
                                #print(k["objects"][val_type]["value"])
                                #print(val_type)
                                if "value" in k["objects"][val_type]:
                                    #print("Inside last for", k["objects"][val_type]["value"])
                                    relevant_info += k["objects"][val_type]["value"] + "\n"
        
            #print("The relevant info is", relevant_info, "\n\n", "End of relevant info")
        
        # Use relevant info

        entrys = nlp(relevant_info)
        matches = matcher(entrys)
        #print("Len og matches is", len(matches))
        if len(matches) > 0:
            
            patterns_ruler = []
            span_list = []
            for match_id, start, end in matches:
                
                str_id = nlp.vocab.strings[match_id]
                span = entrys[start:end]
                if span in span_list:
                    continue
                span_list.append(span)
                #print("This is the matches", match_id, str_id, start, end, span.text)
                patterns_ruler.append({"label": f"{str_id}", "pattern": f"{span.text}"})
            try:
                ruler = nlp.add_pipe("entity_ruler", before="ner")

            except:
                pass    
            ruler.add_patterns(patterns_ruler)
            #print("Added to ruler")
            entrys = nlp(relevant_info)
        all_entries.append([entrys, i[1]])
        #print("The lengt of all entrys is", len(all_entries), "Added", [entrys, i[1]])
        counter += 1
        print(counter)
    return all_entries, rest_list

# This one does not convert stix to json
def find_relevant_spacy_stix(list_of_stuff):
    #print(len(list_of_stuff))
    nlp = spacy.load("en_core_web_sm")
    ruler = nlp.add_pipe("entity_ruler", before="ner")
    patterns_ruler = [
        {"label": "transport", "pattern": "tcp"},
        #{"label": "transport", "pattern": "ip"},
        {"label": "transport", "pattern": "icmp"},
        {"label": "transport", "pattern": "udp"}
    ]

    ruler.add_patterns(patterns_ruler)
    all_entries = []
    all_maches = []
    #list_of_elevated_stuff = []
    #rest_list = []
    
    
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
    patterns_matcher5 = [
        {"TEXT": {"REGEX": r"^{0}(?:\.{0}){{3}}$".format(octet_rx)}},
        {"TEXT": {"REGEX": r"[0-9]{4}?"}, "OP": "+"}
    ]
    patterns_matcher6 = [
        {"ORTH": "Port"},
        {"TEXT": {"REGEX": r"[0-9]{2}?"}, "OP": "+"}
]
    matcher = Matcher(nlp.vocab)
    matcher.add("ipv4", [patterns_matcher])
    matcher.add("MD5", [patterns_matcher2])
    matcher.add("SHA-256", [patterns_matcher3])
    matcher.add("URL", [patterns_matcher4])
    matcher.add("ipv4 and port", [patterns_matcher5])
    matcher.add("Port", [patterns_matcher6])
    
    counter = 0 
    for i in list_of_stuff:
        information = str(i[0])
        information = information.replace("<", " <")
        information = information.replace(">", "> ")
        entrys = nlp(information)
        new_matches = []
        matches = matcher(entrys)
        #print("Len og matches is", len(matches))
        
        
            
            
            
        span_list = []
        for match_id, start, end in matches:
                
            str_id = nlp.vocab.strings[match_id]
            span = entrys[start:end]
            if span in span_list:
                continue
            span_list.append(span)
                #print("This is the matches", match_id, str_id, start, end, span.text)
            new_matches.append([f"{str_id}", f"{span.text}"])
             
        
            #ruler.add_patterns(new_patterns_ruler)
            #print("Added to ruler")
            #entrys = nlp(information)
        all_entries.append([entrys, i[1], new_matches])
        #print("The lengt of all entrys is", len(all_entries), "Added", [entrys, i[1]])
        counter += 1
        if counter % 200 == 0:
            print("Documents processed by spacy", counter)
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
            #print(type(value))
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

    patterns_matcher4 = [
        {"LIKE_URL": True},
        #{"ORTH": "http://vxvault", "OP": "!"}
        ]

    
    
    nlp = spacy.load("en_core_web_sm")
    entrys = nlp(info)
    matcher = Matcher(nlp.vocab)
    matcher.add("ipv4", [patterns_matcher])
    matcher.add("MD5", [patterns_matcher2])
    matcher.add("SHA-256", [patterns_matcher3])
    matcher.add("URL", [patterns_matcher4])
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
    <stix:STIX_Package xmlns:cyboxCommon="http://cybox.mitre.org/common-2" xmlns:cybox="http://cybox.mitre.org/cybox-2" xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2" xmlns:marking="http://data-marking.mitre.org/Marking-1" xmlns:simpleMarking="http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1" xmlns:tlpMarking="http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1" xmlns:TOUMarking="http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1" xmlns:opensource="http://hailataxii.com" xmlns:edge="http://soltra.com/" xmlns:indicator="http://stix.mitre.org/Indicator-2" xmlns:ttp="http://stix.mitre.org/TTP-1" xmlns:stixCommon="http://stix.mitre.org/common-1" xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1" xmlns:stix="http://stix.mitre.org/stix-1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:taxii="http://taxii.mitre.org/messages/taxii_xml_binding-1" xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" xmlns:tdq="http://taxii.mitre.org/query/taxii_default_query-1" id="edge:Package-1d569866-316b-44d7-a19b-bcd865e986d2" version="1.1.1" timestamp="2022-01-27T13:24:36.272541+00:00">
    <stix:STIX_Header>
        <stix:Handling>
            <marking:Marking>
                <marking:Controlled_Structure>../../../../descendant-or-self::node()</marking:Controlled_Structure>
                <marking:Marking_Structure xsi:type="tlpMarking:TLPMarkingStructureType" color="WHITE"/>
                <marking:Marking_Structure xsi:type="TOUMarking:TermsOfUseMarkingStructureType">
                    <TOUMarking:Terms_Of_Use>zeustracker.abuse.ch | Abuse source[https://sslbl.abuse.ch/blacklist/] - As for all abuse.ch projects, the use of the SSL Blacklist is free for both commercial and non-commercial usage without any limitation. However, if you are a commercial vendor of security software/services and you want to integrate data from the SSL Blacklist into your products / services, you will have to ask for permission first by contacting me using the contact form [http://www.abuse.ch/?page_id=4727].'
</TOUMarking:Terms_Of_Use>
                </marking:Marking_Structure>
                <marking:Marking_Structure xsi:type="simpleMarking:SimpleMarkingStructureType">
                    <simpleMarking:Statement>Unclassified (Public)</simpleMarking:Statement>
                </marking:Marking_Structure>
            </marking:Marking>
        </stix:Handling>
    </stix:STIX_Header>
    <stix:Indicators>
        <stix:Indicator id="opensource:indicator-00398022-0d9c-474b-b543-31b85a4f22ab" timestamp="2014-10-31T16:44:24.766014+00:00" xsi:type="indicator:IndicatorType" version="2.1.1">
            <indicator:Title>ZeuS Tracker (offline)| s-k.kiev.ua/html/30/config.bin (2014-10-13) | This domain has been identified as malicious by zeustracker.abuse.ch</indicator:Title>
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Domain Watchlist</indicator:Type>
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">URL Watchlist</indicator:Type>
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
            <indicator:Description>This domain s-k.kiev.ua has been identified as malicious by zeustracker.abuse.ch. For more detailed infomation about this indicator go to [CAUTION!!Read-URL-Before-Click] [https://zeustracker.abuse.ch/monitor.php?host=s-k.kiev.ua].</indicator:Description>
            <indicator:Observable idref="opensource:Observable-94ead651-1df5-4cfe-b4bb-e34ce5e60224">
            </indicator:Observable>
            <indicator:Indicated_TTP>
                <stixCommon:TTP idref="opensource:ttp-6055672f-ecfd-40ae-aa84-0b336a5accb6" xsi:type="ttp:TTPType"/>
            </indicator:Indicated_TTP>
            <indicator:Producer>
                <stixCommon:Identity id="opensource:Identity-3066ae12-3db6-44dd-9636-6b083b6479dc">
                    <stixCommon:Name>zeustracker.abuse.ch</stixCommon:Name>
                </stixCommon:Identity>
                <stixCommon:Time>
                    <cyboxCommon:Produced_Time>2014-10-13T00:00:00+00:00</cyboxCommon:Produced_Time>
                    <cyboxCommon:Received_Time>2014-10-20T19:29:30+00:00</cyboxCommon:Received_Time>
                </stixCommon:Time>
            </indicator:Producer>
        </stix:Indicator>
    </stix:Indicators>
</stix:STIX_Package>
    
    ''', 1
    ], ['''
    <stix:STIX_Package xmlns:cyboxCommon="http://cybox.mitre.org/common-2" xmlns:cybox="http://cybox.mitre.org/cybox-2" xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2" xmlns:marking="http://data-marking.mitre.org/Marking-1" xmlns:simpleMarking="http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1" xmlns:tlpMarking="http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1" xmlns:TOUMarking="http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1" xmlns:opensource="http://hailataxii.com" xmlns:edge="http://soltra.com/" xmlns:indicator="http://stix.mitre.org/Indicator-2" xmlns:ttp="http://stix.mitre.org/TTP-1" xmlns:stixCommon="http://stix.mitre.org/common-1" xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1" xmlns:stix="http://stix.mitre.org/stix-1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:taxii="http://taxii.mitre.org/messages/taxii_xml_binding-1" xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" xmlns:tdq="http://taxii.mitre.org/query/taxii_default_query-1" id="edge:Package-c055cfc7-f653-43b8-844d-6d8c0031d84d" version="1.1.1" timestamp="2022-01-27T13:24:36.297942+00:00">
    <stix:STIX_Header>
        <stix:Handling>
            <marking:Marking>
                <marking:Controlled_Structure>../../../../descendant-or-self::node()</marking:Controlled_Structure>
                <marking:Marking_Structure xsi:type="tlpMarking:TLPMarkingStructureType" color="WHITE"/>
                <marking:Marking_Structure xsi:type="TOUMarking:TermsOfUseMarkingStructureType">
                    <TOUMarking:Terms_Of_Use>feodotracker.abuse.ch | Abuse source[https://sslbl.abuse.ch/blacklist/] - As for all abuse.ch projects, the use of the SSL Blacklist is free for both commercial and non-commercial usage without any limitation. However, if you are a commercial vendor of security software/services and you want to integrate data from the SSL Blacklist into your products / services, you will have to ask for permission first by contacting me using the contact form [http://www.abuse.ch/?page_id=4727].'
</TOUMarking:Terms_Of_Use>
                </marking:Marking_Structure>
                <marking:Marking_Structure xsi:type="simpleMarking:SimpleMarkingStructureType">
                    <simpleMarking:Statement>Unclassified (Public)</simpleMarking:Statement>
                </marking:Marking_Structure>
            </marking:Marking>
        </stix:Handling>
    </stix:STIX_Header>
    <stix:Indicators>
        <stix:Indicator id="opensource:indicator-003b5028-5b86-48c8-a909-5ded675b57ee" timestamp="2015-01-27T16:05:12.590527+00:00" xsi:type="indicator:IndicatorType" version="2.1.1">
            <indicator:Title>Feodo Tracker:  | This IP address has been identified as malicious by feodotracker.abuse.ch</indicator:Title>
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">IP Watchlist</indicator:Type>
            <indicator:Description>This IP address 185.7.151.29 has been identified as malicious by feodotracker.abuse.ch. For more detailed infomation about this indicator go to [CAUTION!!Read-URL-Before-Click] [https://feodotracker.abuse.ch/host/185.7.151.29].</indicator:Description>
            <indicator:Observable idref="opensource:Observable-32c6341a-8bdd-4dba-abb6-ee7b93f8762d">
            </indicator:Observable>
            <indicator:Indicated_TTP>
                <stixCommon:TTP idref="opensource:ttp-3e28f47f-01a9-4f45-94a6-e1ce5bc98de4" xsi:type="ttp:TTPType"/>
            </indicator:Indicated_TTP>
            <indicator:Producer>
                <stixCommon:Identity id="opensource:Identity-71ccf7d8-8d36-44f5-a92e-5bc29fe53271">
                    <stixCommon:Name>feodotracker.abuse.ch</stixCommon:Name>
                </stixCommon:Identity>
                <stixCommon:Time>
                    <cyboxCommon:Produced_Time>2015-01-27T11:21:43+00:00</cyboxCommon:Produced_Time>
                    <cyboxCommon:Received_Time>2015-01-27T16:05:12+00:00</cyboxCommon:Received_Time>
                </stixCommon:Time>
            </indicator:Producer>
        </stix:Indicator>
    </stix:Indicators>
</stix:STIX_Package>
    
    ''', 2
    ], ['''
    <stix:STIX_Package xmlns:cyboxCommon="http://cybox.mitre.org/common-2" xmlns:cybox="http://cybox.mitre.org/cybox-2" xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2" xmlns:marking="http://data-marking.mitre.org/Marking-1" xmlns:simpleMarking="http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1" xmlns:tlpMarking="http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1" xmlns:TOUMarking="http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1" xmlns:opensource="http://hailataxii.com" xmlns:edge="http://soltra.com/" xmlns:indicator="http://stix.mitre.org/Indicator-2" xmlns:ttp="http://stix.mitre.org/TTP-1" xmlns:stixCommon="http://stix.mitre.org/common-1" xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1" xmlns:stix="http://stix.mitre.org/stix-1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:taxii="http://taxii.mitre.org/messages/taxii_xml_binding-1" xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" xmlns:tdq="http://taxii.mitre.org/query/taxii_default_query-1" id="edge:Package-45c5e442-62f4-49c8-9def-23955aeec89a" version="1.1.1" timestamp="2022-01-27T13:24:36.316917+00:00">
    <stix:STIX_Header>
        <stix:Handling>
            <marking:Marking>
                <marking:Controlled_Structure>../../../../descendant-or-self::node()</marking:Controlled_Structure>
                <marking:Marking_Structure xsi:type="tlpMarking:TLPMarkingStructureType" color="WHITE"/>
                <marking:Marking_Structure xsi:type="TOUMarking:TermsOfUseMarkingStructureType">
                    <TOUMarking:Terms_Of_Use>zeustracker.abuse.ch | Abuse source[https://sslbl.abuse.ch/blacklist/] - As for all abuse.ch projects, the use of the SSL Blacklist is free for both commercial and non-commercial usage without any limitation. However, if you are a commercial vendor of security software/services and you want to integrate data from the SSL Blacklist into your products / services, you will have to ask for permission first by contacting me using the contact form [http://www.abuse.ch/?page_id=4727].'
</TOUMarking:Terms_Of_Use>
                </marking:Marking_Structure>
                <marking:Marking_Structure xsi:type="simpleMarking:SimpleMarkingStructureType">
                    <simpleMarking:Statement>Unclassified (Public)</simpleMarking:Statement>
                </marking:Marking_Structure>
            </marking:Marking>
        </stix:Handling>
    </stix:STIX_Header>
    <stix:Indicators>
        <stix:Indicator id="opensource:indicator-0045190c-c35a-4952-b25d-f22b7facbd18" timestamp="2014-12-02T16:05:10.786002+00:00" xsi:type="indicator:IndicatorType" version="2.1.1">
            <indicator:Title>ZeuS Tracker (offline)| 77.74.194.174/js/prince/helps/file.php (2014-12-02) | This IP address has been identified as malicious by zeustracker.abuse.ch</indicator:Title>
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">IP Watchlist</indicator:Type>
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">URL Watchlist</indicator:Type>
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
            <indicator:Description>This IP address 77.74.194.174 has been identified as malicious by zeustracker.abuse.ch. For more detailed infomation about this indicator go to [CAUTION!!Read-URL-Before-Click] [https://zeustracker.abuse.ch/monitor.php?host=77.74.194.174].</indicator:Description>
            <indicator:Observable idref="opensource:Observable-21b6c914-f443-4652-b638-e11fdc2eb949">
            </indicator:Observable>
            <indicator:Indicated_TTP>
                <stixCommon:TTP idref="opensource:ttp-84363a0c-51d6-4a08-89d7-114124783a9d" xsi:type="ttp:TTPType"/>
            </indicator:Indicated_TTP>
            <indicator:Producer>
                <stixCommon:Identity id="opensource:Identity-f5b49298-165b-418c-8b24-c69deb2c384b">
                    <stixCommon:Name>zeustracker.abuse.ch</stixCommon:Name>
                </stixCommon:Identity>
                <stixCommon:Time>
                    <cyboxCommon:Produced_Time>2014-12-02T00:00:00+00:00</cyboxCommon:Produced_Time>
                    <cyboxCommon:Received_Time>2014-12-02T16:05:10+00:00</cyboxCommon:Received_Time>
                </stixCommon:Time>
            </indicator:Producer>
        </stix:Indicator>
    </stix:Indicators>
</stix:STIX_Package>
    
    ''', 3
    ], ['''
    <stix:STIX_Package xmlns:cyboxCommon="http://cybox.mitre.org/common-2" xmlns:cybox="http://cybox.mitre.org/cybox-2" xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2" xmlns:marking="http://data-marking.mitre.org/Marking-1" xmlns:simpleMarking="http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1" xmlns:tlpMarking="http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1" xmlns:TOUMarking="http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1" xmlns:opensource="http://hailataxii.com" xmlns:edge="http://soltra.com/" xmlns:indicator="http://stix.mitre.org/Indicator-2" xmlns:ttp="http://stix.mitre.org/TTP-1" xmlns:stixCommon="http://stix.mitre.org/common-1" xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1" xmlns:stix="http://stix.mitre.org/stix-1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:taxii="http://taxii.mitre.org/messages/taxii_xml_binding-1" xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" xmlns:tdq="http://taxii.mitre.org/query/taxii_default_query-1" id="edge:Package-032481a1-12b0-460c-9d6b-cec21cccca3e" version="1.1.1" timestamp="2022-01-27T13:24:36.349372+00:00">
    <stix:STIX_Header>
        <stix:Handling>
            <marking:Marking>
                <marking:Controlled_Structure>../../../../descendant-or-self::node()</marking:Controlled_Structure>
                <marking:Marking_Structure xsi:type="tlpMarking:TLPMarkingStructureType" color="WHITE"/>
                <marking:Marking_Structure xsi:type="TOUMarking:TermsOfUseMarkingStructureType">
                    <TOUMarking:Terms_Of_Use>zeustracker.abuse.ch | Abuse source[https://sslbl.abuse.ch/blacklist/] - As for all abuse.ch projects, the use of the SSL Blacklist is free for both commercial and non-commercial usage without any limitation. However, if you are a commercial vendor of security software/services and you want to integrate data from the SSL Blacklist into your products / services, you will have to ask for permission first by contacting me using the contact form [http://www.abuse.ch/?page_id=4727].'
</TOUMarking:Terms_Of_Use>
                </marking:Marking_Structure>
                <marking:Marking_Structure xsi:type="simpleMarking:SimpleMarkingStructureType">
                    <simpleMarking:Statement>Unclassified (Public)</simpleMarking:Statement>
                </marking:Marking_Structure>
            </marking:Marking>
        </stix:Handling>
    </stix:STIX_Header>
    <stix:Indicators>
        <stix:Indicator id="opensource:indicator-004c6a0f-a028-4425-b21a-6f81183702d4" timestamp="2015-05-09T15:07:39.375790+00:00" xsi:type="indicator:IndicatorType" version="2.1.1">
            <indicator:Title>ZeuS Tracker (online)| krestenbv.nl/gim/info/mynah.php (2015-05-09) | This domain has been identified as malicious by zeustracker.abuse.ch</indicator:Title>
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Domain Watchlist</indicator:Type>
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">URL Watchlist</indicator:Type>
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
            <indicator:Description>This domain krestenbv.nl has been identified as malicious by zeustracker.abuse.ch. For more detailed infomation about this indicator go to [CAUTION!!Read-URL-Before-Click] [https://zeustracker.abuse.ch/monitor.php?host=krestenbv.nl].</indicator:Description>
            <indicator:Observable idref="opensource:Observable-de98254d-38bf-43e3-bfd3-21ed05c628e1">
            </indicator:Observable>
            <indicator:Indicated_TTP>
                <stixCommon:TTP idref="opensource:ttp-84363a0c-51d6-4a08-89d7-114124783a9d" xsi:type="ttp:TTPType"/>
            </indicator:Indicated_TTP>
            <indicator:Producer>
                <stixCommon:Identity id="opensource:Identity-9882bdb1-4749-4162-8e39-17bee4617980">
                    <stixCommon:Name>zeustracker.abuse.ch</stixCommon:Name>
                </stixCommon:Identity>
                <stixCommon:Time>
                    <cyboxCommon:Produced_Time>2015-05-09T00:00:00+00:00</cyboxCommon:Produced_Time>
                    <cyboxCommon:Received_Time>2015-05-09T15:07:39+00:00</cyboxCommon:Received_Time>
                </stixCommon:Time>
            </indicator:Producer>
        </stix:Indicator>
    </stix:Indicators>
</stix:STIX_Package>
    
    ''', 4
    ]]
    text_description = find_relevant_spacy_list(info)
    entrys = find_relevant_spacy(text_description)
    for ent in entrys.ents:
        spacy_info = ent.text, ent.label_
        print(spacy_info)