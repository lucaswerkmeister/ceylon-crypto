import ceylon.buffer.charset {
    ascii
}
import ceylon.buffer.codec {
    DecodeException
}
import ceylon.time {
    Instant,
    DateTime,
    now
}
import ceylon.time.timezone {
    timeZone,
    zoneDateTime,
    ZoneDateTime
}

shared class GeneralizedTime extends Asn1Value<Instant>
{
    shared new (Byte[] encoded, IdentityInfo identityInfo, Integer lengthOctetsOffset, Integer contentsOctetsOffset, Boolean violatesDer, Instant valu)
            extends Asn1Value<Instant>.direct(encoded, identityInfo, lengthOctetsOffset,  contentsOctetsOffset, violatesDer, valu)
    {}
    
    shared actual String asn1ValueString
    {
        value dateTime = val.dateTime(timeZone.utc);
        value sb = StringBuilder();
        sb.appendCharacter('"');
        sb.append(formatInteger(dateTime.year).padLeading(4, '0'))
            .append(formatInteger(dateTime.month.integer).padLeading(2, '0'))
            .append(formatInteger(dateTime.day).padLeading(2, '0'))
            .append(formatInteger(dateTime.hours).padLeading(2, '0'))
            .append(formatInteger(dateTime.minutes).padLeading(2, '0'))
            .append(formatInteger(dateTime.seconds).padLeading(2, '0'));
        if (dateTime.milliseconds > 0) {
            sb.appendCharacter('.').append(dateTime.milliseconds.string.padLeading(3, '0'));
        }
        sb.append("Z\"");
        return sb.string;
    }
    shared actual Tag defaultTag => UniversalTag.generalizedTime;
}

shared GeneralizedTime | EncodingError generalizedTime(Instant instant, Tag tag = UniversalTag.generalizedTime)
{
    value identityInfo = IdentityInfo(tag, false);
    value identityOctets = identityInfo.encoded;
    value lengthOctetsOffset = identityOctets.size;
    
    DateTime utcValue = instant.dateTime(timeZone.utc);
    StringBuilder stringValue = StringBuilder();
    stringValue.append(utcValue.year.string.padLeading(4, '0'));
    stringValue.append(utcValue.month.integer.string.padLeading(2, '0'));
    stringValue.append(utcValue.day.string.padLeading(2, '0'));
    
    stringValue.append(utcValue.hours.string.padLeading(2, '0'));
    stringValue.append(utcValue.minutes.string.padLeading(2, '0'));
    stringValue.append(utcValue.seconds.string.padLeading(2, '0'));
    
    if (utcValue.milliseconds != 0) {
        stringValue.appendCharacter('.');
        Integer numSubSecondDigits = 3;
        String s = utcValue.milliseconds.string.padLeading(numSubSecondDigits, '0');
        value pos = s.lastIndexWhere((c) => c != '0');
        assert (exists pos);
        stringValue.append(s[0 .. pos]);
    }
    
    stringValue.appendCharacter('Z');

    List<Byte> encodedString = ascii.encode(stringValue);

    value encodedLength = encodeLength(encodedString.size);
    return GeneralizedTime(identityOctets.chain(encodedLength).chain(encodedString).sequence(), identityInfo, lengthOctetsOffset, lengthOctetsOffset + encodedLength.size, false, instant);
}

shared class GeneralizedTimeDecoder(Tag tag = UniversalTag.generalizedTime)
        extends Decoder<GeneralizedTime>(tag)
{
    shared actual [GeneralizedTime, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        Integer nextPos = offset + length;
        
        value contentsOctets = input[offset : length];
        if (contentsOctets.size != length) {
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
        
        value os = GeneralizedTime(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, offset - identityOctetsOffset, violatesDer, zdt.instant);
        return [os, nextPos];
    }
}

shared void zrun()
{
    value x = generalizedTime(now());
    if (is EncodingError x) {
        print(x.message);
        return;
    }
    print(x.encoded);
    print(x.asn1String);
    
    value y = GeneralizedTimeDecoder().decode([24.byte, 17.byte, 48.byte, 48.byte, 48.byte, 49.byte, 48.byte, 50.byte, 50.byte, 56.byte, 48.byte, 48.byte, 48.byte, 48.byte, 53.byte, 48.byte, 46.byte, 48.byte, 90.byte]);
//    value y = GeneralizedTimeDecoder().decode(x.encoded);
    if (is DecodingError y) {
        print(y.message);
        return;
    }
    print(y[0].encoded);
    print(y[0].asn1String);
    assert (!y[0].violatesDer);
}