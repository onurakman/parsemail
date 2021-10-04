package parsemail

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/encoding/ianaindex"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"time"
)

const contentTypeMultipartMixed = "multipart/mixed"
const contentTypeMultipartAlternative = "multipart/alternative"
const contentTypeMultipartRelated = "multipart/related"
const contentTypeTextHtml = "text/html"
const contentTypeTextPlain = "text/plain"
const contentTypeEncapsulatedMessage = "message/rfc822"
const contentTypeOctetStream = "application/octet-stream"
const contentTypeMultipartSigned = "multipart/signed"
const contentAttachment = "attachment"

// Parse an email message read from io.Reader into parsemail.Email struct
func Parse(r io.Reader) (email Email, err error) {
	msg, err := mail.ReadMessage(r)
	if err != nil {
		return
	}

	email, err = createEmailFromHeader(msg.Header)
	if err != nil {
		return
	}

	email.ContentType = msg.Header.Get("Content-Type")
	contentType, params, err := parseContentType(email.ContentType)
	if err != nil {
		return
	}

	if strings.HasPrefix(contentType, "text/") {
		if ch, ok := params["charset"]; ok {
			if converted, charsetErr := charsetReader(ch, msg.Body); charsetErr != nil {
				err = UnknownCharsetError{charsetErr}
			} else {
				msg.Body = converted
			}
		}
	}

	switch contentType {
	case contentTypeMultipartMixed:
		email.TextBody, email.HTMLBody, email.Attachments, email.EmbeddedFiles, email.EmbeddedEmails, err = parseMultipartMixed(msg.Body, params["boundary"])
	case contentTypeMultipartAlternative:
		email.TextBody, email.HTMLBody, email.EmbeddedFiles, err = parseMultipartAlternative(msg.Body, params["boundary"])
	case contentTypeMultipartRelated:
		email.TextBody, email.HTMLBody, email.EmbeddedFiles, err = parseMultipartRelated(msg.Body, params["boundary"])
	case contentTypeMultipartSigned:
		email.TextBody, email.HTMLBody, email.Attachments, email.EmbeddedFiles, email.EmbeddedEmails, err = parseMultipartSigned(msg.Body, params["boundary"])
	case contentTypeTextPlain:
		message, _ := ioutil.ReadAll(msg.Body)
		var reader io.Reader
		reader, err = decodeContent(strings.NewReader(string(message[:])), msg.Header.Get("Content-Transfer-Encoding"))
		if err != nil {
			return
		}

		message, err = ioutil.ReadAll(reader)
		if err != nil {
			return
		}

		email.TextBody = strings.TrimSuffix(string(message[:]), "\n")
	case contentTypeTextHtml:
		message, _ := ioutil.ReadAll(msg.Body)
		var reader io.Reader
		reader, err = decodeContent(strings.NewReader(string(message[:])), msg.Header.Get("Content-Transfer-Encoding"))
		if err != nil {
			return
		}

		message, err = ioutil.ReadAll(reader)
		if err != nil {
			return
		}

		email.HTMLBody = strings.TrimSuffix(string(message[:]), "\n")
	case contentTypeOctetStream:
		email.Attachments, err = parseAttachmentOnlyEmail(msg.Body, msg.Header)
	default:
		email.Content, err = decodeContent(msg.Body, msg.Header.Get("Content-Transfer-Encoding"))
	}

	return
}

func createEmailFromHeader(header mail.Header) (email Email, err error) {
	hp := headerParser{header: &header}

	email.Subject = decodeMimeSentence(header.Get("Subject"))
	email.From = hp.parseAddressList(header.Get("From"))
	email.Sender = hp.parseAddress(header.Get("Sender"))
	email.ReplyTo = hp.parseAddressList(header.Get("Reply-To"))
	email.To = hp.parseAddressList(header.Get("To"))
	email.Cc = hp.parseAddressList(header.Get("Cc"))
	email.Bcc = hp.parseAddressList(header.Get("Bcc"))
	email.Date = hp.parseTime(header.Get("Date"))
	email.ResentFrom = hp.parseAddressList(header.Get("Resent-From"))
	email.ResentSender = hp.parseAddress(header.Get("Resent-Sender"))
	email.ResentTo = hp.parseAddressList(header.Get("Resent-To"))
	email.ResentCc = hp.parseAddressList(header.Get("Resent-Cc"))
	email.ResentBcc = hp.parseAddressList(header.Get("Resent-Bcc"))
	email.ResentMessageID = hp.parseMessageId(header.Get("Resent-Message-ID"))
	email.MessageID = hp.parseMessageId(header.Get("Message-ID"))
	email.InReplyTo = hp.parseMessageIdList(header.Get("In-Reply-To"))
	email.References = hp.parseMessageIdList(header.Get("References"))
	email.ResentDate = hp.parseTime(header.Get("Resent-Date"))

	if hp.err != nil {
		err = hp.err
		return
	}

	//decode whole header for easier access to extra fields
	//todo: should we decode? aren't only standard fields mime encoded?
	email.Header, err = decodeHeaderMime(header)
	if err != nil {
		return
	}

	return
}

func parseContentType(contentTypeHeader string) (contentType string, params map[string]string, err error) {
	if contentTypeHeader == "" {
		contentType = contentTypeTextPlain
		return
	}

	return mime.ParseMediaType(contentTypeHeader)
}

func parseAttachmentOnlyEmail(body io.Reader, header mail.Header) (attachments []Attachment, err error) {
	contentDisposition := header.Get("Content-Disposition")

	if len(contentDisposition) > 0 && strings.Contains(contentDisposition, "attachment;") {
		attachmentData, err := decodeContent(body, header.Get("Content-Transfer-Encoding"))
		if err != nil {
			return attachments, err
		}

		fileName := strings.Replace(contentDisposition, "attachment; filename=\"", "", -1)
		fileName = strings.TrimRight(fileName, "\"")

		at := Attachment{
			Filename:    fileName,
			ContentType: "application/octet-stream",
			Data:        attachmentData,
		}
		attachments = append(attachments, at)
	}

	return attachments, nil
}

func parseMultipartRelated(msg io.Reader, boundary string) (textBody, htmlBody string, embeddedFiles []EmbeddedFile, err error) {
	pmr := multipart.NewReader(msg, boundary)
	for {
		part, err := pmr.NextPart()

		if err == io.EOF {
			break
		} else if err != nil {
			return textBody, htmlBody, embeddedFiles, err
		}

		contentType, params, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			return textBody, htmlBody, embeddedFiles, err
		}

		switch contentType {
		case contentTypeTextPlain:
			message, _ := ioutil.ReadAll(part)
			reader, err := decodeContent(strings.NewReader(string(message[:])), part.Header.Get("Content-Transfer-Encoding"))
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			if ch, ok := params["charset"]; ok {
				rd, err := Reader(ch, reader)
				if err == nil {
					reader = rd
				}
			}

			ppContent, err := ioutil.ReadAll(reader)
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			textBody += strings.TrimSuffix(string(ppContent[:]), "\n")
		case contentTypeTextHtml:
			message, _ := ioutil.ReadAll(part)

			reader, err := decodeContent(strings.NewReader(string(message[:])), part.Header.Get("Content-Transfer-Encoding"))
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			if ch, ok := params["charset"]; ok {
				rd, err := Reader(ch, reader)
				if err == nil {
					reader = rd
				}
			}

			ppContent, err := ioutil.ReadAll(reader)
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			htmlBody += strings.TrimSuffix(string(ppContent[:]), "\n")
		case contentTypeMultipartAlternative:
			tb, hb, ef, err := parseMultipartAlternative(part, params["boundary"])
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			htmlBody += hb
			textBody += tb
			embeddedFiles = append(embeddedFiles, ef...)
		default:
			if isEmbeddedFile(part) {
				ef, err := decodeEmbeddedFile(part)
				if err != nil {
					return textBody, htmlBody, embeddedFiles, err
				}

				embeddedFiles = append(embeddedFiles, ef)
			} else {
				return textBody, htmlBody, embeddedFiles, fmt.Errorf("Can't process multipart/related inner mime type: %s", contentType)
			}
		}
	}

	return textBody, htmlBody, embeddedFiles, err
}

func parseMultipartAlternative(msg io.Reader, boundary string) (textBody, htmlBody string, embeddedFiles []EmbeddedFile, err error) {
	pmr := multipart.NewReader(msg, boundary)
	for {
		part, err := pmr.NextRawPart()

		if err == io.EOF {
			break
		} else if err != nil {
			return textBody, htmlBody, embeddedFiles, err
		}

		contentType, params, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			return textBody, htmlBody, embeddedFiles, err
		}

		switch contentType {
		case contentTypeTextPlain:
			message, _ := ioutil.ReadAll(part)
			reader, err := decodeContent(strings.NewReader(string(message[:])), part.Header.Get("Content-Transfer-Encoding"))
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			if ch, ok := params["charset"]; ok {
				rd, err := Reader(ch, reader)
				if err == nil {
					reader = rd
				}
			}

			ppContent, err := ioutil.ReadAll(reader)
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			textBody += strings.TrimSuffix(string(ppContent[:]), "\n")
		case contentTypeTextHtml:
			message, _ := ioutil.ReadAll(part)

			reader, err := decodeContent(strings.NewReader(string(message[:])), part.Header.Get("Content-Transfer-Encoding"))
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			if ch, ok := params["charset"]; ok {
				rd, err := Reader(ch, reader)
				if err == nil {
					reader = rd
				}
			}

			ppContent, err := ioutil.ReadAll(reader)
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			htmlBody += strings.TrimSuffix(string(ppContent[:]), "\n")
		case contentTypeMultipartRelated:
			tb, hb, ef, err := parseMultipartRelated(part, params["boundary"])
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			htmlBody += hb
			textBody += tb
			embeddedFiles = append(embeddedFiles, ef...)
		default:
			if isEmbeddedFile(part) {
				ef, err := decodeEmbeddedFile(part)
				if err != nil {
					return textBody, htmlBody, embeddedFiles, err
				}

				embeddedFiles = append(embeddedFiles, ef)
			} else {
				return textBody, htmlBody, embeddedFiles, fmt.Errorf("Can't process multipart/alternative inner mime type: %s", contentType)
			}
		}
	}

	return textBody, htmlBody, embeddedFiles, err
}

func parseMultipartMixed(msg io.Reader, boundary string) (textBody, htmlBody string, attachments []Attachment, embeddedFiles []EmbeddedFile, embeddedEmails []Attachment, err error) {
	mr := multipart.NewReader(msg, boundary)
	for {
		part, err := mr.NextRawPart()
		if err == io.EOF {
			err = nil
			break
		} else if err != nil {
			return textBody, htmlBody, attachments, embeddedFiles, embeddedEmails, err
		}

		contentType, params, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			return textBody, htmlBody, attachments, embeddedFiles, embeddedEmails, err
		}

		switch contentType {
		case contentTypeMultipartAlternative:
			textBody, htmlBody, embeddedFiles, err = parseMultipartAlternative(part, params["boundary"])
			if err != nil {
				return textBody, htmlBody, attachments, embeddedFiles, embeddedEmails, err
			}
		case contentTypeMultipartRelated:
			textBody, htmlBody, embeddedFiles, err = parseMultipartRelated(part, params["boundary"])
			if err != nil {
				return textBody, htmlBody, attachments, embeddedFiles, embeddedEmails, err
			}
		case contentTypeTextPlain:
			message, _ := ioutil.ReadAll(part)
			reader, err := decodeContent(strings.NewReader(string(message[:])), part.Header.Get("Content-Transfer-Encoding"))
			if err != nil {
				return textBody, htmlBody, attachments, embeddedFiles, embeddedEmails, err
			}

			if ch, ok := params["charset"]; ok {
				rd, err := Reader(ch, reader)
				if err == nil {
					reader = rd
				}
			}

			ppContent, err := ioutil.ReadAll(reader)
			if err != nil {
				return textBody, htmlBody, attachments, embeddedFiles, embeddedEmails, err
			}

			textBody += strings.TrimSuffix(string(ppContent[:]), "\n")
		case contentTypeTextHtml:
			message, _ := ioutil.ReadAll(part)

			reader, err := decodeContent(strings.NewReader(string(message[:])), part.Header.Get("Content-Transfer-Encoding"))
			if err != nil {
				return textBody, htmlBody, attachments, embeddedFiles, embeddedEmails, err
			}

			if ch, ok := params["charset"]; ok {
				rd, err := Reader(ch, reader)
				if err == nil {
					reader = rd
				}
			}

			ppContent, err := ioutil.ReadAll(reader)
			if err != nil {
				return textBody, htmlBody, attachments, embeddedFiles, embeddedEmails, err
			}

			htmlBody += strings.TrimSuffix(string(ppContent[:]), "\n")
		case contentTypeEncapsulatedMessage:
			// message/rfc822
			email, err := decodeEmbeddedMail(part)
			if err != nil {
				return textBody, htmlBody, attachments, embeddedFiles, embeddedEmails, err
			}
			embeddedEmails = append(embeddedEmails, email)
		case isAttachmentAsString(contentType, part):
			at, err := decodeAttachment(part)
			if err != nil {
				return textBody, htmlBody, attachments, embeddedFiles, embeddedEmails, err
			}

			attachments = append(attachments, at)
		default:
			return textBody, htmlBody, attachments, embeddedFiles, embeddedEmails, fmt.Errorf("Unknown multipart/mixed nested mime type: %s", contentType)
		}
	}

	return textBody, htmlBody, attachments, embeddedFiles, embeddedEmails, err
}

func parseMultipartSigned(msg io.Reader, boundary string) (textBody, htmlBody string, attachments []Attachment, embeddedFiles []EmbeddedFile, embeddedEmails []Attachment, err error) {
	// vars
	err = nil
	var part *multipart.Part
	var contentType string
	var params map[string]string

	// reader
	mr := multipart.NewReader(msg, boundary)

mrparts:
	for {
		part, err = mr.NextRawPart()
		if err == io.EOF {
			err = nil
			break
		} else if err != nil {
			return
		}

		contentType, params, err = mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			return
		}

		switch contentType {
		case contentTypeMultipartMixed:
			if textBody, htmlBody, attachments, embeddedFiles, embeddedEmails, err = parseMultipartMixed(part, params["boundary"]); err != nil {
				break mrparts
			}
		case contentTypeMultipartAlternative:
			if textBody, htmlBody, embeddedFiles, err = parseMultipartAlternative(part, params["boundary"]); err != nil {
				break mrparts
			}
		case contentTypeMultipartRelated:
			if textBody, htmlBody, embeddedFiles, err = parseMultipartRelated(part, params["boundary"]); err != nil {
				break mrparts
			}
		case isAttachmentAsString(contentType, part):
			at, err := decodeAttachment(part)
			if err != nil {
				return textBody, htmlBody, attachments, embeddedFiles, embeddedEmails, err
			}

			attachments = append(attachments, at)
		default:
			err = fmt.Errorf("Unknown multipart/mixed nested mime type: %s", contentType)
			return textBody, htmlBody, attachments, embeddedFiles, embeddedEmails, err
		}

	}

	return textBody, htmlBody, attachments, embeddedFiles, embeddedEmails, err
}

func decodeMimeSentence(s string) string {
	dec := mime.WordDecoder{CharsetReader: charsetReader}
	w, err := dec.DecodeHeader(s)
	if err != nil {
		return s
	}
	return w
}

func isAttachmentAsString(contentType string, part *multipart.Part) string {
	if isAttachment(part) == true {
		return contentType
	}
	return ""
}

func decodeHeaderMime(header mail.Header) (mail.Header, error) {
	parsedHeader := map[string][]string{}

	for headerName, headerData := range header {

		parsedHeaderData := []string{}
		for _, headerValue := range headerData {
			parsedHeaderData = append(parsedHeaderData, decodeMimeSentence(headerValue))
		}

		parsedHeader[headerName] = parsedHeaderData
	}

	return mail.Header(parsedHeader), nil
}

func isEmbeddedFile(part *multipart.Part) bool {
	return part.Header.Get("Content-Transfer-Encoding") != ""
}

func decodeEmbeddedFile(part *multipart.Part) (ef EmbeddedFile, err error) {
	cid := decodeMimeSentence(part.Header.Get("Content-Id"))
	decoded, err := decodeContent(part, part.Header.Get("Content-Transfer-Encoding"))
	if err != nil {
		return
	}

	ef.CID = strings.Trim(cid, "<>")
	ef.Data = decoded
	ef.ContentType = strings.Split(part.Header.Get("Content-Type"), ";")[0]

	return
}

func isAttachment(part *multipart.Part) bool {
	return part.FileName() != ""
}

func decodeAttachment(part *multipart.Part) (at Attachment, err error) {
	filename := decodeMimeSentence(part.FileName())
	decoded, err := decodeContent(part, part.Header.Get("Content-Transfer-Encoding"))
	if err != nil {
		return
	}

	at.Filename = filename
	at.Data = decoded
	at.ContentType = strings.Split(part.Header.Get("Content-Type"), ";")[0]

	return
}

func decodeEmbeddedMail(part *multipart.Part) (at Attachment, err error) {
	msg, err := mail.ReadMessage(part)
	if err != nil {
		return
	}

	email, err := createEmailFromHeader(msg.Header)
	if err != nil {
		return
	}

	filename := decodeMimeSentence(fmt.Sprintf("%s.eml", email.Subject))
	decoded, err := decodeContent(part, part.Header.Get("Content-Transfer-Encoding"))
	if err != nil {
		return
	}

	at.Filename = filename
	at.Data = decoded
	at.ContentType = strings.Split(part.Header.Get("Content-Type"), ";")[0]

	return
}

func decodeContent(content io.Reader, encoding string) (io.Reader, error) {
	switch strings.ToLower(encoding) {
	case "base64":
		decoded := base64.NewDecoder(base64.StdEncoding, content)
		b, err := ioutil.ReadAll(decoded)
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(b), nil
	case "quoted-printable":
		decoded := quotedprintable.NewReader(content)
		b, err := ioutil.ReadAll(decoded)
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(b), nil
	case "7bit", "8bit", "binary":
		dd, err := ioutil.ReadAll(content)
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(dd), nil
	case "":
		return content, nil
	default:
		return nil, fmt.Errorf("unknown encoding: %s", encoding)
	}
}

type headerParser struct {
	header *mail.Header
	err    error
}

func (hp headerParser) parseAddress(s string) (ma *mail.Address) {
	if hp.err != nil {
		return nil
	}

	if strings.Trim(s, " \n") != "" {
		ma, hp.err = mail.ParseAddress(s)
		return ma
	}

	return nil
}

func (hp headerParser) parseAddressList(s string) (ma []*mail.Address) {
	if hp.err != nil {
		return
	}

	if strings.Trim(s, " \n") != "" {
		ma, hp.err = mail.ParseAddressList(s)
		return
	}

	return
}

func (hp headerParser) parseTime(s string) (t time.Time) {
	if hp.err != nil || s == "" {
		return
	}

	formats := []string{
		time.RFC1123Z,
		"Mon, 2 Jan 2006 15:04:05 -0700",
		time.RFC1123Z + " (MST)",
		"Mon, 2 Jan 2006 15:04:05 -0700 (MST)",
	}

	for _, format := range formats {
		t, hp.err = time.Parse(format, s)
		if hp.err == nil {
			return
		}
	}

	return
}

func (hp headerParser) parseMessageId(s string) string {
	if hp.err != nil {
		return ""
	}

	return strings.Trim(s, "<> ")
}

func (hp headerParser) parseMessageIdList(s string) (result []string) {
	if hp.err != nil {
		return
	}

	for _, p := range strings.Split(s, " ") {
		if strings.Trim(p, " \n") != "" {
			result = append(result, hp.parseMessageId(p))
		}
	}

	return
}

// Attachment with filename, content type and data (as a io.Reader)
type Attachment struct {
	Filename    string
	ContentType string
	Data        io.Reader
}

// EmbeddedFile with content id, content type and data (as a io.Reader)
type EmbeddedFile struct {
	CID         string
	ContentType string
	Data        io.Reader
}

// Email with fields for all the headers defined in RFC5322 with it's attachments and
type Email struct {
	Header mail.Header

	Subject    string
	Sender     *mail.Address
	From       []*mail.Address
	ReplyTo    []*mail.Address
	To         []*mail.Address
	Cc         []*mail.Address
	Bcc        []*mail.Address
	Date       time.Time
	MessageID  string
	InReplyTo  []string
	References []string

	ResentFrom      []*mail.Address
	ResentSender    *mail.Address
	ResentTo        []*mail.Address
	ResentDate      time.Time
	ResentCc        []*mail.Address
	ResentBcc       []*mail.Address
	ResentMessageID string

	ContentType string
	Content     io.Reader

	HTMLBody string
	TextBody string

	Attachments    []Attachment
	EmbeddedFiles  []EmbeddedFile
	EmbeddedEmails []Attachment
}

type UnknownCharsetError struct {
	e error
}

func (u UnknownCharsetError) Unwrap() error { return u.e }

func (u UnknownCharsetError) Error() string {
	return "unknown charset: " + u.e.Error()
}

// IsUnknownCharset returns a boolean indicating whether the error is known to
// report that the charset advertised by the entity is unknown.
func IsUnknownCharset(err error) bool {
	return errors.As(err, new(UnknownCharsetError))
}

// CharsetReader , if non-nil, defines a function to generate charset-conversion
// readers, converting from the provided charset into UTF-8. Charsets are always
// lower-case. utf-8 and us-ascii charsets are handled by default. One of the
// CharsetReader's result values must be non-nil.
//
// Importing github.com/emersion/go-message/charset will set CharsetReader to
// a function that handles most common charsets. Alternatively, CharsetReader
// can be set to e.g. golang.org/x/net/html/charset.NewReaderLabel.
var CharsetReader func(charset string, input io.Reader) (io.Reader, error)

// charsetReader calls CharsetReader if non-nil.
func charsetReader(charset string, input io.Reader) (io.Reader, error) {
	charset = strings.ToLower(charset)
	if charset == "utf-8" || charset == "us-ascii" {
		return input, nil
	}
	if CharsetReader != nil {
		r, err := CharsetReader(charset, input)
		if err != nil {
			return r, UnknownCharsetError{err}
		}
		return r, nil
	}
	return input, UnknownCharsetError{fmt.Errorf("message: unhandled charset %q", charset)}
}

// decodeHeader decodes an internationalized header field. If it fails, it
// returns the input string and the error.
func decodeHeader(s string) (string, error) {
	wordDecoder := mime.WordDecoder{CharsetReader: charsetReader}
	dec, err := wordDecoder.DecodeHeader(s)
	if err != nil {
		return s, err
	}
	return dec, nil
}

func encodeHeader(s string) string {
	return mime.QEncoding.Encode("utf-8", s)
}

var charsets = map[string]encoding.Encoding{
	"ansi_x3.110-1983": charmap.ISO8859_1, // see RFC 1345 page 62, mostly superset of ISO 8859-1
}

func init() {
	CharsetReader = Reader
}

// Reader returns an io.Reader that converts the provided charset to UTF-8.
func Reader(charset string, input io.Reader) (io.Reader, error) {
	var err error
	enc, ok := charsets[strings.ToLower(charset)]
	if ok && enc == nil {
		return nil, fmt.Errorf("charset %q: charset is disabled", charset)
	} else if !ok {
		enc, err = ianaindex.MIME.Encoding(charset)
	}
	if enc == nil {
		enc, err = ianaindex.MIME.Encoding("cs" + charset)
	}
	if enc == nil {
		enc, err = htmlindex.Get(charset)
	}
	if err != nil {
		return nil, fmt.Errorf("charset %q: %v", charset, err)
	}
	// See https://github.com/golang/go/issues/19421
	if enc == nil {
		return nil, fmt.Errorf("charset %q: unsupported charset", charset)
	}
	return enc.NewDecoder().Reader(input), nil
}

// RegisterEncoding registers an encoding. This is intended to be called from
// the init function in packages that want to support additional charsets.
func RegisterEncoding(name string, enc encoding.Encoding) {
	charsets[name] = enc
}
