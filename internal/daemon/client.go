package daemon

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"jailor/internal/api"
	"jailor/internal/image"
)

type Client struct {
	socket string
}

func NewClient(socketPath string) *Client {
	return &Client{socket: socketPath}
}

func (c *Client) Socket() string { return c.socket }

func (c *Client) call(method string, params any) (json.RawMessage, *api.Error) {
	conn, err := net.DialTimeout("unix", c.socket, time.Duration(DialTimeout))
	if err != nil {
		return nil, api.Internal(fmt.Errorf("cannot reach jailord at %s: %w", c.socket, err))
	}
	defer conn.Close()
	body, err := marshalParams(params)
	if err != nil {
		return nil, api.Internal(err)
	}
	if err := json.NewEncoder(conn).Encode(api.Request{Version: api.Version, Method: method, Params: body}); err != nil {
		return nil, api.Internal(fmt.Errorf("write request: %w", err))
	}
	var resp api.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, api.Internal(fmt.Errorf("decode response: %w", err))
	}
	if !resp.OK {
		if resp.Error == nil {
			resp.Error = api.Internal(fmt.Errorf("daemon refused %s", method))
		}
		return nil, resp.Error
	}
	return resp.Data, nil
}

func marshalParams(v any) (json.RawMessage, error) {
	if v == nil {
		return nil, nil
	}
	return json.Marshal(v)
}

func (c *Client) Ping() *api.Error {
	_, aerr := c.call(api.MethodPing, nil)
	return aerr
}

func (c *Client) Version() (*api.VersionInfo, *api.Error) {
	data, aerr := c.call(api.MethodVersion, nil)
	if aerr != nil {
		return nil, aerr
	}
	var info api.VersionInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, api.Internal(err)
	}
	return &info, nil
}

func (c *Client) Create(j api.Jail) (string, *api.Error) {
	data, aerr := c.call(api.MethodCreate, api.CreateParams{Jail: j})
	if aerr != nil {
		return "", aerr
	}
	var res api.IDResult
	if err := json.Unmarshal(data, &res); err != nil {
		return "", api.Internal(err)
	}
	return res.ID, nil
}

func (c *Client) Run(j api.Jail) (api.RunResult, *api.Error) {
	data, aerr := c.call(api.MethodRun, api.RunParams{Jail: j})
	if aerr != nil {
		return api.RunResult{}, aerr
	}
	var res api.RunResult
	if err := json.Unmarshal(data, &res); err != nil {
		return api.RunResult{}, api.Internal(err)
	}
	return res, nil
}

func (c *Client) Start(id string) (int, *api.Error) {
	data, aerr := c.call(api.MethodStart, api.IDParams{ID: id})
	if aerr != nil {
		return 0, aerr
	}
	code, err := codeFrom(data)
	if err != nil {
		return 0, api.Internal(err)
	}
	return code, nil
}

func (c *Client) Stop(id string) (int, *api.Error) {
	data, aerr := c.call(api.MethodStop, api.IDParams{ID: id})
	if aerr != nil {
		return 0, aerr
	}
	code, err := codeFrom(data)
	if err != nil {
		return 0, api.Internal(err)
	}
	return code, nil
}

func (c *Client) Kill(id string) (int, *api.Error) {
	data, aerr := c.call(api.MethodKill, api.IDParams{ID: id})
	if aerr != nil {
		return 0, aerr
	}
	code, err := codeFrom(data)
	if err != nil {
		return 0, api.Internal(err)
	}
	return code, nil
}

func (c *Client) Restart(id string) (int, *api.Error) {
	data, aerr := c.call(api.MethodRestart, api.IDParams{ID: id})
	if aerr != nil {
		return 0, aerr
	}
	code, err := codeFrom(data)
	if err != nil {
		return 0, api.Internal(err)
	}
	return code, nil
}

func (c *Client) Remove(id string) *api.Error {
	_, aerr := c.call(api.MethodRemove, api.IDParams{ID: id})
	return aerr
}

func (c *Client) List() (api.JailList, *api.Error) {
	data, aerr := c.call(api.MethodList, nil)
	if aerr != nil {
		return api.JailList{}, aerr
	}
	var out api.JailList
	if err := json.Unmarshal(data, &out); err != nil {
		return api.JailList{}, api.Internal(err)
	}
	return out, nil
}

func (c *Client) Inspect(id string) (api.JailRecord, *api.Error) {
	data, aerr := c.call(api.MethodInspect, api.IDParams{ID: id})
	if aerr != nil {
		return api.JailRecord{}, aerr
	}
	var out api.JailRecord
	if err := json.Unmarshal(data, &out); err != nil {
		return api.JailRecord{}, api.Internal(err)
	}
	return out, nil
}

func (c *Client) Stats(id string) (api.RationsStats, *api.Error) {
	data, aerr := c.call(api.MethodStats, api.IDParams{ID: id})
	if aerr != nil {
		return api.RationsStats{}, aerr
	}
	var out api.RationsStats
	if err := json.Unmarshal(data, &out); err != nil {
		return api.RationsStats{}, api.Internal(err)
	}
	return out, nil
}

func (c *Client) Logs(id string) (api.JailLogs, *api.Error) {
	data, aerr := c.call(api.MethodLogs, api.IDParams{ID: id})
	if aerr != nil {
		return api.JailLogs{}, aerr
	}
	var out api.JailLogs
	if err := json.Unmarshal(data, &out); err != nil {
		return api.JailLogs{}, api.Internal(err)
	}
	return out, nil
}

func (c *Client) Images() (api.ImageList, *api.Error) {
	data, aerr := c.call(api.MethodImageList, nil)
	if aerr != nil {
		return api.ImageList{}, aerr
	}
	var out api.ImageList
	if err := json.Unmarshal(data, &out); err != nil {
		return api.ImageList{}, api.Internal(err)
	}
	return out, nil
}

func (c *Client) ImageInspect(ref string) (image.Image, *api.Error) {
	data, aerr := c.call(api.MethodImageInspect, api.ImageParams{Ref: ref})
	if aerr != nil {
		return image.Image{}, aerr
	}
	var out image.Image
	if err := json.Unmarshal(data, &out); err != nil {
		return image.Image{}, api.Internal(err)
	}
	return out, nil
}

func (c *Client) ImageRemove(ref string) (int, *api.Error) {
	data, aerr := c.call(api.MethodImageRemove, api.ImageParams{Ref: ref})
	if aerr != nil {
		return 0, aerr
	}
	var out api.CountResult
	if err := json.Unmarshal(data, &out); err != nil {
		return 0, api.Internal(err)
	}
	return out.Count, nil
}

func (c *Client) NetworkCreate(p api.NetworkParams) (api.NetworkResult, *api.Error) {
	data, aerr := c.call(api.MethodNetworkCreate, p)
	if aerr != nil {
		return api.NetworkResult{}, aerr
	}
	var out api.NetworkResult
	if err := json.Unmarshal(data, &out); err != nil {
		return api.NetworkResult{}, api.Internal(err)
	}
	return out, nil
}

func (c *Client) NetworkList() (api.NetworkResult, *api.Error) {
	data, aerr := c.call(api.MethodNetworkList, nil)
	if aerr != nil {
		return api.NetworkResult{}, aerr
	}
	var out api.NetworkResult
	if err := json.Unmarshal(data, &out); err != nil {
		return api.NetworkResult{}, api.Internal(err)
	}
	return out, nil
}

func (c *Client) NetworkInspect(name string) (api.NetworkResult, *api.Error) {
	data, aerr := c.call(api.MethodNetworkInspect, api.NetworkParams{Name: name})
	if aerr != nil {
		return api.NetworkResult{}, aerr
	}
	var out api.NetworkResult
	if err := json.Unmarshal(data, &out); err != nil {
		return api.NetworkResult{}, api.Internal(err)
	}
	return out, nil
}

func (c *Client) NetworkRemove(name string) (int, *api.Error) {
	data, aerr := c.call(api.MethodNetworkRemove, api.NetworkParams{Name: name})
	if aerr != nil {
		return 0, aerr
	}
	var out api.CountResult
	if err := json.Unmarshal(data, &out); err != nil {
		return 0, api.Internal(err)
	}
	return out.Count, nil
}

func (c *Client) Shutdown() *api.Error {
	_, aerr := c.call(api.MethodShutdown, nil)
	return aerr
}

func (c *Client) Events() (*EventStream, *api.Error) {
	conn, err := net.DialTimeout("unix", c.socket, time.Duration(DialTimeout))
	if err != nil {
		return nil, api.Internal(fmt.Errorf("cannot reach jailord at %s: %w", c.socket, err))
	}
	if err := json.NewEncoder(conn).Encode(api.Request{Version: api.Version, Method: api.MethodEvents}); err != nil {
		_ = conn.Close()
		return nil, api.Internal(err)
	}
	stream := &EventStream{conn: conn, dec: json.NewDecoder(conn)}
	if _, err := stream.NextWithin(10 * time.Second); err != nil {
		_ = conn.Close()
		return nil, api.Internal(fmt.Errorf("event stream subscription failed: %w", err))
	}
	return stream, nil
}

type EventStream struct {
	conn net.Conn
	dec  *json.Decoder
}

func (s *EventStream) Next() (*api.Event, error) {
	var ev api.Event
	if err := s.dec.Decode(&ev); err != nil {
		return nil, err
	}
	return &ev, nil
}

func (s *EventStream) NextWithin(d time.Duration) (*api.Event, error) {
	if err := s.conn.SetReadDeadline(time.Now().Add(d)); err != nil {
		return nil, err
	}
	defer func() {
		_ = s.conn.SetReadDeadline(time.Time{})
	}()
	return s.Next()
}

func (s *EventStream) Close() {
	if s.conn != nil {
		_ = s.conn.Close()
	}
}

func codeFrom(data json.RawMessage) (int, error) {
	var res struct {
		ExitCode int `json:"exitCode"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return 0, err
	}
	return res.ExitCode, nil
}
