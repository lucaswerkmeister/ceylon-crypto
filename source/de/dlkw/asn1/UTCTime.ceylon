import ceylon.time {
    Instant,
    DateTime
}
import ceylon.time.timezone {
    ZoneDateTime,
    timeZone
}
import ceylon.buffer.charset {
    ascii
}
import ceylon.time.iso8601 {
    parseZoneDateTime,
    parseDateTime
}
import ceylon.buffer.codec {
    DecodeException
}
shared class UTCTime(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, valu, dateTime)
         extends Asn1Value<String>(encoded, identityInfo, lengthOctetsOffset,  contentsOctetsOffset, violatesDer, valu)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    String valu;
    shared DateTime | ZoneDateTime dateTime;

    
    shared actual String asn1ValueString
    {
        return "\"``valu``\"";
    }
    shared actual Tag defaultTag = UniversalTag.utcTime;
}

shared UTCTime | EncodingError utcTimeFromInstant(Instant instant, Tag tag = UniversalTag.utcTime)
{
    value identityInfo = IdentityInfo(tag, false);
    value identityOctets = identityInfo.encoded;
    value lengthOctetsOffset = identityOctets.size;
    
    ZoneDateTime zoneDateTime = instant.zoneDateTime(timeZone.utc);
    StringBuilder stringValue = StringBuilder();
    stringValue.append((zoneDateTime.year % 100).string.padLeading(2, '0'));
    stringValue.append(zoneDateTime.month.integer.string.padLeading(2, '0'));
    stringValue.append(zoneDateTime.day.string.padLeading(2, '0'));
    
    stringValue.append(zoneDateTime.hours.string.padLeading(2, '0'));
    stringValue.append(zoneDateTime.minutes.string.padLeading(2, '0'));
    stringValue.append(zoneDateTime.seconds.string.padLeading(2, '0'));
    
    if (zoneDateTime.milliseconds != 0) {
        stringValue.appendCharacter('.');
        Integer numSubSecondDigits = 3;
        String s = zoneDateTime.milliseconds.string.padLeading(numSubSecondDigits, '0');
        value pos = s.lastIndexWhere((c) => c != '0');
        assert (exists pos);
        stringValue.append(s[0 .. pos]);
    }
    
    stringValue.appendCharacter('Z');
    
    List<Byte> encodedString = ascii.encode(stringValue);
    
    value encodedLength = encodeLength(encodedString.size);
    return UTCTime(identityOctets.chain(encodedLength).chain(encodedString).sequence(), identityInfo, lengthOctetsOffset, lengthOctetsOffset + encodedLength.size, false, stringValue.string, zoneDateTime);
}

shared UTCTime | EncodingError utcTimeFromString(String stringValue, Integer latestYearRepresentable, Tag tag = UniversalTag.utcTime)
{
    value identityInfo = IdentityInfo(tag, false);
    value identityOctets = identityInfo.encoded;
    value lengthOctetsOffset = identityOctets.size;

    value encoded = utcTimeFromStringInternal(stringValue, latestYearRepresentable);
    if (is EncodingError encoded) {
        return encoded;
    }
    
    value encodedLength = encodeLength(encoded[0].size);
    return UTCTime(identityOctets.chain(encodedLength).chain(encoded[0]).sequence(), identityInfo, lengthOctetsOffset, lengthOctetsOffset + encodedLength.size, encoded[2], stringValue, encoded[1]);
}

[List<Byte>, <DateTime | ZoneDateTime>, Boolean] | EncodingError utcTimeFromStringInternal(String stringValue, Integer latestYearRepresentable)
{
    variable Boolean violatesDer = false;
    
    if (latestYearRepresentable < 100) {
        return EncodingError("latestYearRepresentable < 100");
    }
    Integer century = latestYearRepresentable / 100;
    Integer latestYearLast2Dig = latestYearRepresentable % 100;

    value length = stringValue.size;
    if (length < 8) {
        return EncodingError("too few characters for UTCTime");
    }

    Integer? encodedYear = parseInteger(stringValue[0:2]);
    if (is Null encodedYear) {
        return EncodingError("first two characters not digits");
    }
    if (encodedYear < 0) {
        return EncodingError("first two characters not digits");
    }
    
    String withCentury;
    if (encodedYear <= latestYearLast2Dig) {
        withCentury = century.string.padLeading(2, '0') + stringValue;
    }
    else {
        withCentury = (century - 1).string.padLeading(2, '0') + stringValue;
    }
    
    value datePart = withCentury[0:8];
    if (datePart.any((c) => c == 'W')) {
        return EncodingError("illegal character 'W' in UTCTime");
    }
    
    value timePart = withCentury[8...];
    if (exists point = timePart.firstIndexWhere((c) => c in ".,")) {
        if (point < 6) {
            violatesDer = true;
        }
        assert (exists p = timePart[point]);
        if (p == ',') {
            violatesDer = true;
        }
        assert (exists z = timePart.last);
        if (p != 'Z') {
            violatesDer = true;
        }
    }
    
    value isoString = "``datePart``T``withCentury[8...]``";
    print(isoString);
    
    Boolean useZone;
    if (exists c = withCentury.last, c == 'Z') {
        useZone = true;
    }
    else {
        useZone = withCentury.lastIndexWhere((c) => c in ['+', '-']) exists;
    }
    
    ZoneDateTime | DateTime zdt;
    if (useZone) {
        value zoneDateTime = parseZoneDateTime(isoString);
        if (is Null zoneDateTime) {
            return EncodingError("not a valid gt string");
        }
        zdt = zoneDateTime;
    }
    else {
        value dateTime = parseDateTime(isoString);
        if (is Null dateTime) {
            return EncodingError("not a valid gt string");
        }
        zdt = dateTime;
    }
    
    List<Byte> encodedString = ascii.encode(stringValue);
    print(zdt);
    print(stringValue);
    
    return [encodedString, zdt, violatesDer];
}

shared class UTCTimeDecoder(Integer latestYearRepresentable, Tag tag = UniversalTag.utcTime)
        extends Decoder<UTCTime>(tag)
{
    shared actual [UTCTime, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        Integer nextPos = offset + length;
        
        value contentsOctets = input[offset : length];
        if (contentsOctets.shorterThan(length)) {
            return DecodingError(offset + contentsOctets.size, "reached end of input");
        }
        
        String string;
        try {
            string = ascii.decode(contentsOctets);
        }
        catch (DecodeException e) {
            return DecodingError(offset, "Cannot decode UTCTime: ``e.message``");
        }
        
        value encoded = utcTimeFromStringInternal(string, latestYearRepresentable);
        if (is EncodingError encoded) {
            return DecodingError(offset, encoded.message);
        }
        
        value encodedLength = encodeLength(encoded[0].size);
        violatesDer ||= encoded[2];
        
        value os = UTCTime(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, offset - identityOctetsOffset, violatesDer, string, encoded[1]);
        return [os, nextPos];
    }
}

shared void xxu()
{
    value t = utcTimeFromString("32100910", 1831);
    if (is EncodingError t) {
        print(t.message);
        return;
    }
    print(t.val);
}
