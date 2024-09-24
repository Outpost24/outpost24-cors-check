package com.t0xodile.checkcors.corsCheckExtension

import burp.api.montoya.core.Marker
import burp.api.montoya.http.message.HttpRequestResponse

fun randSting(length: Int): String {
    val chars = "abcdefghijklmnopqrstucwxyz"
    return (1..length).map{ chars.random() }.joinToString("")
}

fun getMarkerFromResponse(requestResponse: HttpRequestResponse, match: String): Marker? {
    val start = requestResponse.response().toString().indexOf(match, 0)
    val end = start+match.length
    val marker = Marker.marker(start, end)
    return marker
}

fun getMarkerFromRequest(requestResponse: HttpRequestResponse, match: String): Marker? {
    val start = requestResponse.request().toString().indexOf(match, 0)
    val end = start+match.length
    val marker = Marker.marker(start, end)
    return marker
}