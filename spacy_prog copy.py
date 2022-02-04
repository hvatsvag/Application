#import stix2viz
from stix2elevator import elevate
from stix2elevator.options import initialize_options, set_option_value
import json
import spacy
from spacy.matcher import Matcher




def find_relevant_spacy_list(list_of_stuff):
    initialize_options(options={"spec_version": "2.0"})
    nlp = spacy.load("en_core_web_sm")
    all_entries = []
    
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
        json_info = elevate(text)
        json_info = json.loads(json_info)

        relevant_info = ""

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
            ruler = nlp.add_pipe("entity_ruler", before="ner")
            ruler.add_patterns(patterns_ruler)
            entrys = nlp(relevant_info)
        all_entries.append([entrys, i[1]])


        


def find_relevant_info(info):
    initialize_options(options={"spec_version": "2.0"})
    json_info = elevate(info)
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
                    relevant_info += k["description"] + "\n"
                if "definition" in k and "statement" in k["definition"]:
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
    return relevant_info

def find_relevant_spacy(info):
    #info = info.replace(",", " ,")
    #info = info.replace(".", " .")
    #print(info)
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
    print(type(entrys))
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
    info ='''
    <stix:STIX_Package xmlns:FileObj="http://cybox.mitre.org/objects#FileObject-2" xmlns:cybox="http://cybox.mitre.org/cybox-2" xmlns:cyboxCommon="http://cybox.mitre.org/common-2" xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2" xmlns:indicator="http://stix.mitre.org/Indicator-2" xmlns:stix="http://stix.mitre.org/stix-1" xmlns:stixCommon="http://stix.mitre.org/common-1" xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1" xmlns:ttp="http://stix.mitre.org/TTP-1" xmlns:vxvault="http://vxvault.net" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:taxii="http://taxii.mitre.org/messages/taxii_xml_binding-1" xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" xmlns:tdq="http://taxii.mitre.org/query/taxii_default_query-1" id="vxvault:Package-a1b6fe54-b118-4a56-9331-a1e12fbda441" version="1.2">
    <stix:Indicators>
        <stix:Indicator id="vxvault:indicator-fc959723-9e5c-4db3-a2a3-1a9ec21e8cb8" timestamp="2010-03-10T00:00:00+00:00" xsi:type="indicator:IndicatorType">
            <indicator:Title>VxVault reporting on Malware Trojan.Win32.Vilsel.vbe with name load_2.exe found at URL  (None)</indicator:Title>
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">Malware Artifacts</indicator:Type>
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">File Hash Watchlist</indicator:Type>
            <indicator:Description>VxVault reports the presence of a Trojan.Win32.Vilsel.vbe Malware at  (None) with the following characteristics: name: load_2.exe, MD5: 7BAEC745C469A7C63F5B24D824A0315B, SHA-256: None.</indicator:Description>
            <indicator:Valid_Time_Position>
                <indicator:Start_Time precision="second">2010-03-10T00:00:00+00:00</indicator:Start_Time>
            </indicator:Valid_Time_Position>
            <indicator:Observable id="vxvault:Observable-add2fe3c-670e-43b8-a74c-d2ab184ca8d2">
                <cybox:Object id="vxvault:File-e9695330-3d41-40eb-bc57-57a79083f5c2">
                    <cybox:Properties xsi:type="FileObj:FileObjectType">
                        <FileObj:File_Name>load_2.exe</FileObj:File_Name>
                        <FileObj:Size_In_Bytes>17920</FileObj:Size_In_Bytes>
                        <FileObj:Hashes>
                            <cyboxCommon:Hash>
                                <cyboxCommon:Type xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA1</cyboxCommon:Type>
                                <cyboxCommon:Simple_Hash_Value>749489E4F35600AFF5EAFA11408CA8902DEA348F</cyboxCommon:Simple_Hash_Value>
                            </cyboxCommon:Hash>
                            <cyboxCommon:Hash>
                                <cyboxCommon:Type xsi:type="cyboxVocabs:HashNameVocab-1.0">MD5</cyboxCommon:Type>
                                <cyboxCommon:Simple_Hash_Value>7BAEC745C469A7C63F5B24D824A0315B</cyboxCommon:Simple_Hash_Value>
                            </cyboxCommon:Hash>
                        </FileObj:Hashes>
                    </cybox:Properties>
                </cybox:Object>
            </indicator:Observable>
            <indicator:Indicated_TTP>
                <stixCommon:TTP id="vxvault:ttp-e1615131-ebdf-410f-a297-824daeaa4cec" timestamp="2010-03-10T00:00:00+00:00" xsi:type="ttp:TTPType">
                    <ttp:Title>Trojan.Win32.Vilsel.vbe</ttp:Title>
                    <ttp:Behavior>
                        <ttp:Malware>
                            <ttp:Malware_Instance>
                                <ttp:Name>Trojan.Win32.Vilsel.vbe</ttp:Name>
                            </ttp:Malware_Instance>
                        </ttp:Malware>
                    </ttp:Behavior>
                </stixCommon:TTP>
            </indicator:Indicated_TTP>
            <indicator:Kill_Chain_Phases>
                <stixCommon:Kill_Chain_Phase phase_id="stix:TTP-79a0e041-9d5f-49bb-ada4-8322622b162d" kill_chain_id="stix:TTP-af3e707f-2fb9-49e5-8c37-14026ca0a5ff"/>
            </indicator:Kill_Chain_Phases>
            <indicator:Confidence timestamp="2010-03-10T00:00:00+00:00">
                <stixCommon:Value xsi:type="stixVocabs:HighMediumLowVocab-1.0">Medium</stixCommon:Value>
            </indicator:Confidence>
            <indicator:Producer>
                <stixCommon:Description>Sourced from VxVault,located at http://vxvault.net/ViriFiche.php?ID=3111</stixCommon:Description>
                <stixCommon:Identity>
                    <stixCommon:Name>VxVault: http://vxvault.net/ViriFiche.php?ID=3111</stixCommon:Name>
                </stixCommon:Identity>
                <stixCommon:Contributing_Sources>
                    <stixCommon:Source>
                        <stixCommon:Description>http://vxvault.net/ViriFiche.php?ID=3111</stixCommon:Description>
                    </stixCommon:Source>
                </stixCommon:Contributing_Sources>
                <stixCommon:Time>
                    <cyboxCommon:Produced_Time>2010-03-10T00:00:00+00:00</cyboxCommon:Produced_Time>
                </stixCommon:Time>
                <stixCommon:References>
                    <stixCommon:Reference>http://pedump.me/7baec745c469a7c63f5b24d824a0315b</stixCommon:Reference>
                    <stixCommon:Reference>http://urlquery.net/search.php?q=&amp;type=string&amp;start=2014-08-26&amp;end=2015-08-26&amp;max=50</stixCommon:Reference>
                    <stixCommon:Reference>https://totalhash.cymru.com/search/?ip:</stixCommon:Reference>
                    <stixCommon:Reference>http://www.threatexpert.com/report.aspx?md5=7BAEC745C469A7C63F5B24D824A0315B</stixCommon:Reference>
                    <stixCommon:Reference>http://secuboxlabs.fr/kolab/api?hash=749489E4F35600AFF5EAFA11408CA8902DEA348F&amp;key=9</stixCommon:Reference>
                    <stixCommon:Reference>https://www.hybrid-analysis.com/search?query=</stixCommon:Reference>
                    <stixCommon:Reference>http://vxvault.net/ViriFiche.php?ID=3111</stixCommon:Reference>
                </stixCommon:References>
            </indicator:Producer>
        </stix:Indicator>
    </stix:Indicators>
    <stix:TTPs>
        <stix:Kill_Chains>
            <stixCommon:Kill_Chain reference="http://www.lockheedmartin.com/content/dam/lockheed/data/corporate/documents/LM-White-Paper-Intel-Driven-Defense.pdf" id="stix:TTP-af3e707f-2fb9-49e5-8c37-14026ca0a5ff" definer="LMCO" name="LM Cyber Kill Chain">
                <stixCommon:Kill_Chain_Phase ordinality="1" name="Reconnaissance" phase_id="stix:TTP-af1016d6-a744-4ed7-ac91-00fe2272185a"/>
                <stixCommon:Kill_Chain_Phase ordinality="2" name="Weaponization" phase_id="stix:TTP-445b4827-3cca-42bd-8421-f2e947133c16"/>
                <stixCommon:Kill_Chain_Phase ordinality="3" name="Delivery" phase_id="stix:TTP-79a0e041-9d5f-49bb-ada4-8322622b162d"/>
                <stixCommon:Kill_Chain_Phase ordinality="4" name="Exploitation" phase_id="stix:TTP-f706e4e7-53d8-44ef-967f-81535c9db7d0"/>
                <stixCommon:Kill_Chain_Phase ordinality="5" name="Installation" phase_id="stix:TTP-e1e4e3f7-be3b-4b39-b80a-a593cfd99a4f"/>
                <stixCommon:Kill_Chain_Phase ordinality="6" name="Command and Control" phase_id="stix:TTP-d6dc32b9-2538-4951-8733-3cb9ef1daae2"/>
                <stixCommon:Kill_Chain_Phase ordinality="7" name="Actions on Objectives" phase_id="stix:TTP-786ca8f9-2d9a-4213-b38e-399af4a2e5d6"/>
            </stixCommon:Kill_Chain>
        </stix:Kill_Chains>
    </stix:TTPs>
</stix:STIX_Package>
    
    '''
    text_description = find_relevant_info(info)
    entrys = find_relevant_spacy(text_description)
    for ent in entrys.ents:
        spacy_info = ent.text, ent.label_
        print(spacy_info)