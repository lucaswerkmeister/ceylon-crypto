import ceylon.buffer.charset {
    ascii
}
import ceylon.buffer.codec {
    DecodeException
}
import ceylon.time {
    Instant,
    DateTime
}
import ceylon.time.iso8601 {
    parseZoneDateTime,
    parseDateTime
}
import ceylon.time.timezone {
    timeZone,
    ZoneDateTime,
    zoneDateTime
}

shared class GeneralizedTime(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer, valu, dateTime)
        extends Asn1Value<String>(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer, valu)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentOctetsOffset;
    Boolean violatesDer;
    String valu;
    shared DateTime | ZoneDateTime dateTime;

    shared actual String asn1ValueString
    {
        return "\"``valu``\"";
    }
    shared actual Tag defaultTag => UniversalTag.generalizedTime;
}

shared GeneralizedTime | EncodingError generalizedTimeFromInstant(Instant instant, Tag tag = UniversalTag.generalizedTime)
{
    value identityInfo = IdentityInfo(tag, false);
    value identityOctets = identityInfo.encoded;
    value lengthOctetsOffset = identityOctets.size;
    
    ZoneDateTime zoneDateTime = instant.zoneDateTime(timeZone.utc);
    StringBuilder stringValue = StringBuilder();
    stringValue.append(zoneDateTime.year.string.padLeading(4, '0'));
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
    return GeneralizedTime(identityOctets.chain(encodedLength).chain(encodedString).sequence(), identityInfo, lengthOctetsOffset, lengthOctetsOffset + encodedLength.size, false, stringValue.string, zoneDateTime);
}

shared GeneralizedTime | EncodingError generalizedTimeFromString(String stringValue, Tag tag = UniversalTag.generalizedTime)
{
    value identityInfo = IdentityInfo(tag, false);
    value identityOctets = identityInfo.encoded;
    value lengthOctetsOffset = identityOctets.size;
    
    value length = stringValue.size;
    if (length < 10) {
        return EncodingError("too few characters for GeneralizedTime");
    }
    
    value datePart = stringValue[0:8];
    if (datePart.any((c) => c == 'W')) {
        return EncodingError("illegal character 'W' in GeneralizedTime");
    }
    
    value isoString = "``datePart``T``stringValue[8...]``";
    print(isoString);
    
    Boolean useZone;
    if (exists c = stringValue.last, c == 'Z') {
        useZone = true;
    }
    else {
        useZone = stringValue.lastIndexWhere((c) => c in ['+', '-']) exists;
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
    
    value encodedLength = encodeLength(encodedString.size);
    return GeneralizedTime(identityOctets.chain(encodedLength).chain(encodedString).sequence(), identityInfo, lengthOctetsOffset, lengthOctetsOffset + encodedLength.size, false, stringValue, zdt);
}

shared class GeneralizedTimeDecoder(Tag tag = UniversalTag.generalizedTime)
        extends Decoder<GeneralizedTime>(tag)
{
    shared actual [GeneralizedTime, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
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
            return DecodingError(offset, "Cannot decode GeneralizedTime: ``e.message``");
        }

        Integer stringLength = string.size;
        if (stringLength < 15) {
            return DecodingError(lengthOctetsOffset, "Length of GeneralizedTime must be at least 15");
        }

        value year = parseInteger(string[0:4]);
        if (is Null year) {
            return DecodingError(offset, "Invalid year \"``string[0:4]``\"");
        }
        if (year < 0) {
            return DecodingError(offset, "Invalid year \"``string[0:4]``\"");
        }
        value month = parseInteger(string[4:2]);
        if (is Null month) {
            return DecodingError(offset + 4, "Invalid month \"``string[4:2]``\"");
        }
        value day = parseInteger(string[6:2]);
        if (is Null day) {
            return DecodingError(offset + 6, "Invalid day \"``string[6:2]``\"");
        }
        value hour = parseInteger(string[8:2]);
        if (is Null hour) {
            return DecodingError(offset + 8, "Invalid day \"``string[8:2]``\"");
        }
        value minute = parseInteger(string[10:2]);
        if (is Null minute) {
            return DecodingError(offset + 10, "Invalid day \"``string[10:2]``\"");
        }
        value second = parseInteger(string[12:2]);
        if (is Null second) {
            return DecodingError(offset + 12, "Invalid day \"``string[12:2]``\"");
        }
        
        Integer milliseconds;
        assert (exists c = string[14]);
        if (c == '.') {
            assert (exists zulu = string[stringLength - 1]);
            if (zulu != 'Z') {
                return DecodingError(offset, "Fractional seconds part of GeneralizedTime must be followed by 'Z'");
            }
            value msString = string[15 .. stringLength - 2];
            if (msString.empty) {
                violatesDer ||= true;
                milliseconds = 0;
            }
            else {
                // TODO check for 0s only
                value padded = msString.padTrailing(3, '0');
                if (padded.any((c)=>c < '0' || c > '9')) {
                    return DecodingError(offset + 15, "Invalid fractional seconds value for GeneralizedTime");
                }
                assert (exists parsed = parseInteger(padded[0:3]));
                milliseconds = parsed;
            }
        }
        else if (c == 'Z') {
            if (stringLength != 15) {
                return DecodingError(offset + 15, "spurious contents after Z in GeneralizedTime");
            }
            milliseconds = 0;
        }
        else {
            return DecodingError(offset + 14, "Seconds part of GeneralizedTime must be followed by 'Z' or '.'");
        }
        ZoneDateTime zdt;
        try {
            zdt = zoneDateTime(timeZone.utc, year, month, day, hour, minute, second, milliseconds);
        }
        catch (AssertionError e) {
            return DecodingError(offset, "Cannot decode GeneralizedTime: ``e.message``");
        }
        
        value os = GeneralizedTime(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, offset - identityOctetsOffset, violatesDer, string, zdt);
        return [os, nextPos];
    }
}
