package app.protoclean.protocols

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ImportParserTest {

    @Test fun detectsSupportedSchemes() {
        assertEquals("hysteria2", ImportParser.schemeOf("hy2://x@h:1")?.let { ImportParser.kindOf(it) })
        assertEquals("shadowsocks", ImportParser.kindOf("ss"))
        assertEquals("amneziawg", ImportParser.kindOf("awg"))
        assertEquals("boxraw", ImportParser.kindOf("singbox"))
        assertNull(ImportParser.schemeOf("ftp://x"))
        assertNull(ImportParser.schemeOf("no-scheme"))
    }

    @Test fun parsesHostPortAndName() {
        val p = ImportParser.parse("hysteria2://auth@h.example.com:8443/?sni=h#my%20server")!!
        assertEquals("hysteria2", p.kind)
        assertEquals("h.example.com", p.server)
        assertEquals(8443, p.port)
        assertEquals("my%20server", p.name)
    }

    @Test fun defaultsPortsPerKind() {
        assertEquals(443, ImportParser.parse("vless://u@v.io")?.port)
        assertEquals(8388, ImportParser.parse("ss://x@1.2.3.4")?.port)
        assertEquals(2408, ImportParser.parse("warp://config")?.port)
    }

    @Test fun handlesIpv6Hosts() {
        val p = ImportParser.parse("tuic://u:p@[2001:db8::1]:443?sni=x#v6")!!
        assertEquals("2001:db8::1", p.server)
        assertEquals(443, p.port)
    }

    @Test fun parseAllSkipsCommentsAndDuplicates() {
        val text = """
            # subscription
            trojan://pw@t.io:443?sni=t.io#one
            trojan://pw@t.io:443?sni=t.io#one
            not a link
            vmess://eyJ2IjoiMiJ9
        """.trimIndent()
        val all = ImportParser.parseAll(text)
        assertEquals(2, all.size)
        assertEquals("trojan", all[0].kind)
        assertEquals("vmess", all[1].kind)
    }

    @Test fun detectsConfigDocuments() {
        assertTrue(ImportParser.looksLikeConfig("{\"outbounds\":[]}"))
        assertTrue(ImportParser.looksLikeConfig("proxies:\n- name: x"))
        assertTrue(ImportParser.looksLikeConfig("[Interface]\nPrivateKey=x"))
        assertTrue(ImportParser.looksLikeConfig("client\ndev tun"))
        assertFalse(ImportParser.looksLikeConfig("ss://x@1.2.3.4:1#y"))
    }
}
