package models

type CDATAText struct {
	Text string `xml:",innerxml"`
}

func Value2CDATA(v string) CDATAText {
	//return CDATAText{[]byte("<![CDATA[" + v + "]]>")}
	return CDATAText{"<![CDATA[" + v + "]]>"}
}
