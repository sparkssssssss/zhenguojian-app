package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type nativeStreamAsset struct {
	address     string
	data        []byte
	contentType string
	total       int64
	etag        string
	modified    string
}

type nativeStreamSession struct {
	credentials *providerMediaCredentials
	mu          sync.Mutex
	assets      map[string]nativeStreamAsset
	referer     string
	key         []byte
	cenc        *cencTrack
	ctx         context.Context
	cancel      context.CancelFunc
	lastUsed    time.Time
}

type nativeStreamServer struct {
	mu         sync.Mutex
	downloader *Downloader
	address    string
	sessions   map[string]*nativeStreamSession
	server     *http.Server
}

func (stream *nativeStreamServer) nativeRequest(request *http.Request) (*http.Response, error) {
	client := *stream.downloader.client
	client.Timeout = 0
	return stream.downloader.doMediaRequestWithClient(request, &client)
}

var nativePlaylistURI = regexp.MustCompile(`URI="([^"]+)"`)

func newNativeStreamServer(d *Downloader) (*nativeStreamServer, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, errors.New("无法初始化本机播放器")
	}
	stream := &nativeStreamServer{downloader: d, address: "http://" + listener.Addr().String(), sessions: map[string]*nativeStreamSession{}}
	server := &http.Server{Handler: http.HandlerFunc(stream.nativeServe), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	stream.server = server
	go func() { _ = server.Serve(listener) }()
	return stream, nil
}

func (stream *nativeStreamServer) nativeOpen(media providerMedia) (string, string) {
	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		panic(err)
	}
	token := hex.EncodeToString(tokenBytes)
	ctx, cancel := context.WithCancel(providerMediaContext(context.Background(), media.credentials))
	session := &nativeStreamSession{assets: map[string]nativeStreamAsset{}, referer: media.Referer, key: media.HLSKey, ctx: ctx, cancel: cancel, lastUsed: time.Now(), credentials: media.credentials}
	stream.mu.Lock()
	for id, old := range stream.sessions {
		if time.Since(old.lastUsed) > 10*time.Minute {
			old.cancel()
			delete(stream.sessions, id)
		}
	}
	if len(stream.sessions) >= 8 {
		oldest := ""
		for id, old := range stream.sessions {
			if oldest == "" || old.lastUsed.Before(stream.sessions[oldest].lastUsed) {
				oldest = id
			}
		}
		stream.sessions[oldest].cancel()
		delete(stream.sessions, oldest)
	}
	stream.sessions[token] = session
	stream.mu.Unlock()
	entry := nativeStreamAsset{address: media.URL, contentType: "video/mp4"}
	if parsed, err := url.Parse(media.URL); err == nil && strings.HasSuffix(strings.ToLower(parsed.Path), ".m3u8") {
		entry.contentType = "application/vnd.apple.mpegurl"
	}
	if media.Playlist != "" {
		entry.data = []byte(media.Playlist)
		entry.contentType = "application/vnd.apple.mpegurl"
	}
	if media.CENCKey != nil && len(media.CENCKey) == 16 && !strings.HasSuffix(strings.ToLower(media.URL), ".m3u8") {
		if track := stream.nativeBuildCENC(ctx, media); track != nil {
			session.cenc = track
		}
	}
	return stream.nativeAsset(token, session, entry), token
}

// nativeBuildCENC 拉取流头部（moov + IV 表），构建 CENC 解密上下文。
// 红果流的 moov 约 200KB、IV 表约 40KB（4911×8），1MB 头部预算充足。
func (stream *nativeStreamServer) nativeBuildCENC(ctx context.Context, media providerMedia) *cencTrack {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, media.URL, nil)
	if err != nil {
		return nil
	}
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("Referer", media.Referer)
	request.Header.Set("Range", "bytes=0-1048575")
	request.Header.Set("Accept-Encoding", "identity")
	response, err := stream.nativeRequest(request)
	if err != nil {
		return nil
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusPartialContent {
		return nil
	}
	head, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil || len(head) < 32 {
		return nil
	}
	parsed, err := cencParseMoov(head)
	if err != nil {
		return nil
	}
	track := &cencTrack{Samples: parsed.Samples}
	copy(track.Key[:], media.CENCKey)
	last := parsed.Samples[len(parsed.Samples)-1]
	ivEnd := parsed.IV.Base + int64(parsed.IV.Count)*8
	if ivEnd > int64(len(head)) {
		return nil
	}
	track.IVBytes = append([]byte(nil), head[parsed.IV.Base:ivEnd]...)
	_ = last
	return track
}

func (stream *nativeStreamServer) nativeRelease(token string) {
	stream.mu.Lock()
	if session := stream.sessions[token]; session != nil {
		session.cancel()
		delete(stream.sessions, token)
	}
	stream.mu.Unlock()
}

func (stream *nativeStreamServer) nativeAsset(token string, session *nativeStreamSession, asset nativeStreamAsset) string {
	digest := sha256.Sum256([]byte(asset.address + "\x00" + asset.contentType))
	extension := ".ts"
	if parsed, err := url.Parse(asset.address); err == nil {
		switch candidate := strings.ToLower(path.Ext(parsed.Path)); candidate {
		case ".m3u8", ".ts", ".m4s", ".mp4", ".aac", ".m4a", ".mp3", ".vtt", ".webvtt", ".key":
			extension = candidate
		}
	}
	switch asset.contentType {
	case "application/vnd.apple.mpegurl":
		extension = ".m3u8"
	case "application/octet-stream":
		extension = ".key"
	case "video/mp4":
		extension = ".mp4"
	}
	id := hex.EncodeToString(digest[:12]) + extension
	session.mu.Lock()
	if previous, found := session.assets[id]; !found || len(previous.data) == 0 || len(asset.data) > 0 {
		session.assets[id] = asset
	}
	session.mu.Unlock()
	return stream.address + "/" + token + "/" + id
}

func (stream *nativeStreamServer) nativeRewrite(token string, session *nativeStreamSession, body, base string) (string, error) {
	var output []string
	nextPlaylist := false
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		text := strings.TrimSpace(line)
		rewrite := func(reference string, key bool, contentType string) string {
			if strings.HasPrefix(reference, "data:") {
				return reference
			}
			parsed, err := url.Parse(base)
			if err != nil {
				return ""
			}
			relative, err := url.Parse(reference)
			if err != nil {
				return ""
			}
			address := parsed.ResolveReference(relative).String()
			if !isProviderHTTPMediaURL(address) {
				return ""
			}
			asset := nativeStreamAsset{address: address, contentType: contentType}
			if key && len(session.key) == 16 {
				asset.data = append([]byte{}, session.key...)
				asset.contentType = "application/octet-stream"
			}
			return stream.nativeAsset(token, session, asset)
		}
		if text != "" && !strings.HasPrefix(text, "#") {
			contentType := ""
			if nextPlaylist {
				contentType = "application/vnd.apple.mpegurl"
			}
			line = rewrite(text, false, contentType)
			nextPlaylist = false
			if line == "" {
				return "", errors.New("播放列表中的媒体地址无效")
			}
		} else if strings.Contains(text, "URI=") {
			invalid := false
			line = nativePlaylistURI.ReplaceAllStringFunc(line, func(match string) string {
				reference := nativePlaylistURI.FindStringSubmatch(match)[1]
				key := strings.HasPrefix(text, "#EXT-X-KEY:") || strings.HasPrefix(text, "#EXT-X-SESSION-KEY:")
				contentType := ""
				switch {
				case key:
					contentType = "application/octet-stream"
				case strings.HasPrefix(text, "#EXT-X-MAP:"):
					contentType = "video/mp4"
				case strings.HasPrefix(text, "#EXT-X-MEDIA:"), strings.HasPrefix(text, "#EXT-X-I-FRAME-STREAM-INF:"), strings.HasPrefix(text, "#EXT-X-RENDITION-REPORT:"):
					contentType = "application/vnd.apple.mpegurl"
				}
				updated := rewrite(reference, key, contentType)
				if updated == "" {
					invalid = true
				}
				return "URI=\"" + updated + "\""
			})
			if invalid {
				return "", errors.New("播放列表中的附属地址无效")
			}
		}
		if strings.HasPrefix(text, "#EXT-X-STREAM-INF:") {
			nextPlaylist = true
		}
		output = append(output, line)
	}
	return strings.Join(output, "\n"), nil
}

func (stream *nativeStreamServer) nativeServe(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(parts) != 2 {
		http.NotFound(writer, request)
		return
	}
	stream.mu.Lock()
	session := stream.sessions[parts[0]]
	if session != nil {
		session.lastUsed = time.Now()
	}
	stream.mu.Unlock()
	if session == nil {
		http.Error(writer, "播放已结束", http.StatusGone)
		return
	}
	session.mu.Lock()
	asset, found := session.assets[parts[1]]
	session.mu.Unlock()
	if !found {
		http.NotFound(writer, request)
		return
	}
	ctx, cancel := context.WithCancel(providerMediaContext(request.Context(), session.credentials))
	defer cancel()
	stop := context.AfterFunc(session.ctx, cancel)
	defer stop()
	writer.Header().Set("Cache-Control", "no-store")
	if len(asset.data) > 0 && asset.total > int64(len(asset.data)) {
		if stream.nativeServePrefix(ctx, writer, request, session, asset) {
			return
		}
		asset.data = nil
	}
	if len(asset.data) > 0 {
		if strings.Contains(asset.contentType, "mpegurl") {
			body, err := stream.nativeRewrite(parts[0], session, string(asset.data), asset.address)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadGateway)
				return
			}
			writer.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
			if request.Method == http.MethodGet {
				_, _ = io.WriteString(writer, body)
			}
		} else {
			writer.Header().Set("Content-Type", asset.contentType)
			if asset.etag != "" {
				writer.Header().Set("ETag", asset.etag)
			}
			http.ServeContent(writer, request, parts[1], time.Time{}, bytes.NewReader(asset.data))
		}
		return
	}
	upstream, err := http.NewRequestWithContext(ctx, request.Method, asset.address, nil)
	if err != nil {
		http.Error(writer, "媒体地址无效", http.StatusBadGateway)
		return
	}
	upstream.Header.Set("User-Agent", userAgent)
	upstream.Header.Set("Referer", session.referer)
	for _, name := range []string{"Range", "If-Range"} {
		if value := request.Header.Get(name); value != "" {
			upstream.Header.Set(name, value)
		}
	}
	response, err := stream.nativeRequest(upstream)
	if err != nil {
		http.Error(writer, "读取媒体失败，请重试", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusPartialContent {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		err := stream.downloader.catalogResponseError(upstream, response, body)
		http.Error(writer, err.Error(), response.StatusCode)
		return
	}
	contentType := strings.ToLower(response.Header.Get("Content-Type"))
	finalURL := upstream.URL
	if response.Request != nil && response.Request.URL != nil {
		finalURL = response.Request.URL
	}
	playlist := strings.Contains(asset.contentType, "mpegurl") || strings.Contains(contentType, "mpegurl") || strings.HasSuffix(strings.ToLower(finalURL.Path), ".m3u8")
	if playlist && request.Method == http.MethodHead {
		writer.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		writer.WriteHeader(http.StatusOK)
		return
	}
	if playlist && request.Method == http.MethodGet {
		body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20+1))
		if err != nil || len(body) > 4<<20 {
			http.Error(writer, "播放列表过大或读取失败", http.StatusBadGateway)
			return
		}
		text := strings.TrimSpace(strings.TrimPrefix(string(body), "\ufeff"))
		if !strings.HasPrefix(text, "#EXTM3U") {
			http.Error(writer, "播放列表无效", http.StatusBadGateway)
			return
		}
		rewritten, err := stream.nativeRewrite(parts[0], session, text, finalURL.String())
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadGateway)
			return
		}
		writer.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		_, _ = io.WriteString(writer, rewritten)
		return
	}
	if session.cenc != nil {
		stream.nativeServeCENC(writer, request, session, asset, response)
		return
	}
	for _, name := range []string{"Content-Type", "Content-Length", "Content-Range", "Accept-Ranges", "ETag", "Last-Modified"} {
		if value := response.Header.Get(name); value != "" {
			writer.Header().Set(name, value)
		}
	}
	writer.WriteHeader(response.StatusCode)
	if request.Method == http.MethodGet {
		_, _ = io.Copy(writer, response.Body)
	}
}

// nativeServeCENC 按播放器的 Range 请求解密对应样本区间后回传。
func (stream *nativeStreamServer) nativeServeCENC(writer http.ResponseWriter, request *http.Request,
	session *nativeStreamSession, asset nativeStreamAsset, response *http.Response) {
	rangeHeader := request.Header.Get("Range")
	var start, end int64 = 0, -1
	if rangeHeader != "" {
		if parsed := parseByteRange(rangeHeader); parsed != nil {
			start, end = parsed[0], parsed[1]
		}
	}
	if start < 0 {
		http.Error(writer, "Range 头无效", http.StatusRequestedRangeNotSatisfiable)
		return
	}
	lastSample := session.cenc.Samples[len(session.cenc.Samples)-1]
	total := lastSample.Offset + lastSample.Length
	if end < 0 || end >= total {
		// 开放式请求（bytes=0-）只回前 8MB：播放器会按需继续 Range，
		// 避免一次性下载/解密整集导致起播慢、内存峰值高。
		end = start + (8 << 20) - 1
		if end >= total {
			end = total - 1
		}
	}
	length := end - start + 1
	if length <= 0 {
		writer.Header().Set("Content-Range", "bytes */"+strconv64(total))
		writer.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}
	// 向后对齐 16 字节块（可能跨出一个样本，多解密无害）
	alignedStart := start - start%16
	upstream, err := http.NewRequestWithContext(request.Context(), http.MethodGet, asset.address, nil)
	if err != nil {
		http.Error(writer, "媒体地址无效", http.StatusBadGateway)
		return
	}
	upstream.Header.Set("User-Agent", userAgent)
	upstream.Header.Set("Referer", session.referer)
	upstream.Header.Set("Range", "bytes="+strconv64(alignedStart)+"-"+strconv64(end))
	upstream.Header.Set("Accept-Encoding", "identity")
	upstreamResponse, err := stream.nativeRequest(upstream)
	if err != nil {
		http.Error(writer, "读取媒体失败，请重试", http.StatusBadGateway)
		return
	}
	defer upstreamResponse.Body.Close()
	if upstreamResponse.StatusCode != http.StatusPartialContent && upstreamResponse.StatusCode != http.StatusOK {
		http.Error(writer, "读取媒体失败", upstreamResponse.StatusCode)
		return
	}
	cipherText, err := io.ReadAll(io.LimitReader(upstreamResponse.Body, length+(alignedStart-start)+64<<10))
	if err != nil {
		http.Error(writer, "读取媒体失败，请重试", http.StatusBadGateway)
		return
	}
	plain, err := session.cenc.decryptRange(cipherText, alignedStart)
	if err != nil {
		http.Error(writer, "解密失败", http.StatusBadGateway)
		return
	}
	skip := int(start - alignedStart)
	if skip > len(plain) {
		skip = len(plain)
	}
	payload := plain[skip:]
	if int64(len(payload)) > length {
		payload = payload[:length]
	}
	writer.Header().Set("Content-Type", "video/mp4")
	writer.Header().Set("Accept-Ranges", "bytes")
	writer.Header().Set("Content-Range", "bytes "+strconv64(start)+"-"+strconv64(start+int64(len(payload))-1)+"/"+strconv64(total))
	writer.Header().Set("Content-Length", strconv64(int64(len(payload))))
	writer.WriteHeader(http.StatusPartialContent)
	if request.Method == http.MethodGet {
		_, _ = writer.Write(payload)
	}
}

func parseByteRange(header string) []int64 {
	parts := strings.SplitN(header, "=", 2)
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "bytes") {
		return nil
	}
	span := strings.SplitN(parts[1], "-", 2)
	if len(span) != 2 {
		return nil
	}
	start, err := strconv.ParseInt(span[0], 10, 64)
	if err != nil || start < 0 {
		return nil
	}
	end := int64(-1)
	if span[1] != "" {
		if end, err = strconv.ParseInt(span[1], 10, 64); err != nil {
			return nil
		}
	}
	return []int64{start, end}
}

func strconv64(value int64) string {
	return strconv.FormatInt(value, 10)
}
