defmodule Ueberauth.Strategy.GoogleTest do
  use ExUnit.Case, async: true
  use Plug.Test

  import Mock
  import Plug.Conn
  alias Plug.Conn.Query
  import Ueberauth.Strategy.Helpers

  setup_with_mocks([
    {UeberauthOidcc.Callback, [:passthrough],
     [
       handle_callback: &oidcc_handle_callback/2
     ]}
  ]) do
    # Create a connection with Ueberauth's CSRF cookies so they can be recycled during tests
    routes = Ueberauth.init([])

    csrf_conn = conn(:get, "/auth/google", %{}) |> init_test_session(%{}) |> Ueberauth.call(routes)

    csrf_state = with_state_param([], csrf_conn) |> Keyword.get(:state)

    {:ok, csrf_conn: csrf_conn, csrf_state: csrf_state}
  end

  def set_options(routes, conn, opt) do
    case Enum.find_index(routes, &(elem(&1, 0) == {conn.request_path, conn.method})) do
      nil ->
        routes

      idx ->
        update_in(routes, [Access.at(idx), Access.elem(1), Access.elem(2)], &%{&1 | options: opt})
    end
  end

  def oidcc_handle_callback(opts, conn)

  def oidcc_handle_callback(_opts, %{params: %{"code" => "success_code"}} = conn) do
    token = %Oidcc.Token{
      access: %Oidcc.Token.Access{
        token: "success_token"
      },
      id: %Oidcc.Token.Id{
        claims: %{}
      }
    }

    userinfo = %{
      "sub" => "1234_fred",
      "name" => "Fred Jones",
      "email" => "fred_jones@example.com"
    }

    {:ok, conn, token, userinfo}
  end

  def oidcc_handle_callback(_opts, %{params: %{"code" => "uid_code"}} = conn) do
    token = %Oidcc.Token{
      access: %Oidcc.Token.Access{
        token: "uid_token"
      },
      id: %Oidcc.Token.Id{
        claims: %{}
      }
    }

    userinfo = %{
      "uid_field" => "1234_daphne",
      "name" => "Daphne Blake"
    }

    {:ok, conn, token, userinfo}
  end

  def oidcc_handle_callback(
        %{userinfo_endpoint: "example.com/shaggy"},
        %{params: %{"code" => "userinfo_code"}} = conn
      ) do
    token = %Oidcc.Token{
      access: %Oidcc.Token.Access{
        token: "userinfo_token"
      },
      id: %Oidcc.Token.Id{
        claims: %{}
      }
    }

    userinfo = %{"sub" => "1234_shaggy", "name" => "Norville Rogers"}

    {:ok, conn, token, userinfo}
  end

  def oidcc_handle_callback(
        %{userinfo_endpoint: "example.com/scooby"},
        %{params: %{"code" => "userinfo_code"}} = conn
      ) do
    token = %Oidcc.Token{
      access: %Oidcc.Token.Access{
        token: "userinfo_token"
      },
      id: %Oidcc.Token.Id{
        claims: %{}
      }
    }

    userinfo = %{"sub" => "1234_scooby", "name" => "Scooby Doo"}

    {:ok, conn, token, userinfo}
  end

  def oidcc_handle_callback(
        _opts,
        %{params: %{"code" => "userinfo_code"}} = conn
      ) do
    token = %Oidcc.Token{
      access: %Oidcc.Token.Access{
        token: "userinfo_token"
      },
      id: %Oidcc.Token.Id{
        claims: %{}
      }
    }

    userinfo = %{
      "sub" => "1234_velma",
      "name" => "Velma Dinkley"
    }

    {:ok, conn, token, userinfo}
  end

  def oidcc_handle_callback(
        %{client_secret: "custom_client_secret"},
        %{params: %{"code" => "client_secret_code"}} = conn
      ) do
    token = %Oidcc.Token{
      access: %Oidcc.Token.Access{
        token: "success_token"
      },
      id: %Oidcc.Token.Id{
        claims: %{}
      }
    }

    userinfo = %{
      "sub" => "1234_fred",
      "name" => "Fred Jones",
      "email" => "fred_jones@example.com"
    }

    {:ok, conn, token, userinfo}
  end

  def oidcc_handle_callback(
        _opts,
        %{params: %{"code" => "oauth2_error"}} = conn
      ) do
    {:error, conn, :timeout}
  end

  def oidcc_handle_callback(
        _opts,
        %{params: %{"code" => "error_response"}} = conn
      ) do
    {:error, conn, {:http_error, 401, %{"error" => "some error", "error_description" => "something went wrong"}}}
  end

  def oidcc_handle_callback(
        _opts,
        %{params: %{"code" => "error_response_no_description"}} = conn
      ) do
    {:error, conn, {:http_error, 401, %{"error" => "internal_failure"}}}
  end

  def oidcc_handle_callback(_opts, conn) do
    {:error, conn, :not_defined}
  end

  def oidcc_retrieve_userinfo(
        "userinfo_token",
        %{provider_configuration: %{userinfo_endpoint: "example.com/scooby"}},
        _opts
      ) do
    {:ok, %{"sub" => "1234_scooby", "name" => "Scooby Doo"}}
  end

  def oidcc_retrieve_userinfo(_token, _client_context, _opts) do
    {:error, :not_defined}
  end

  defp set_csrf_cookies(conn, csrf_conn) do
    conn
    |> init_test_session(%{})
    |> recycle_cookies(csrf_conn)
    |> fetch_cookies()
  end

  test "handle_request! redirects to appropriate auth uri" do
    conn = conn(:get, "/auth/google", %{hl: "es"}) |> init_test_session(%{})

    # Make sure the hd and scope params are included for good measure
    routes = Ueberauth.init() |> set_options(conn, hd: "example.com", default_scope: "email openid")

    resp = Ueberauth.call(conn, routes)

    assert resp.status == 302
    assert [location] = get_resp_header(resp, "location")

    redirect_uri = URI.parse(location)
    assert redirect_uri.host == "accounts.google.com"
    assert redirect_uri.path == "/o/oauth2/v2/auth"

    assert %{
             "client_id" => "client_id",
             "redirect_uri" => "http://www.example.com/auth/google/callback",
             "response_type" => "code",
             "scope" => "email openid",
             "hd" => "example.com",
             "hl" => "es"
           } = Query.decode(redirect_uri.query)
  end

  test "handle_callback! assigns required fields on successful auth", %{
    csrf_state: csrf_state,
    csrf_conn: csrf_conn
  } do
    conn =
      conn(:get, "/auth/google/callback", %{code: "success_code", state: csrf_state})
      |> set_csrf_cookies(csrf_conn)

    routes = Ueberauth.init([])
    assert %Plug.Conn{assigns: %{ueberauth_auth: auth}} = Ueberauth.call(conn, routes)
    assert auth.credentials.token == "success_token"
    assert auth.info.name == "Fred Jones"
    assert auth.info.email == "fred_jones@example.com"
    assert auth.uid == "1234_fred"
  end

  test "uid_field is picked according to the specified option", %{
    csrf_state: csrf_state,
    csrf_conn: csrf_conn
  } do
    conn =
      conn(:get, "/auth/google/callback", %{code: "uid_code", state: csrf_state})
      |> set_csrf_cookies(csrf_conn)

    routes = Ueberauth.init() |> set_options(conn, uid_field: "uid_field")
    assert %Plug.Conn{assigns: %{ueberauth_auth: auth}} = Ueberauth.call(conn, routes)
    assert auth.info.name == "Daphne Blake"
    assert auth.uid == "1234_daphne"
  end

  test "userinfo is fetched according to userinfo_endpoint", %{
    csrf_state: csrf_state,
    csrf_conn: csrf_conn
  } do
    conn =
      conn(:get, "/auth/google/callback", %{code: "userinfo_code", state: csrf_state})
      |> set_csrf_cookies(csrf_conn)

    routes = Ueberauth.init() |> set_options(conn, userinfo_endpoint: "example.com/shaggy")
    assert %Plug.Conn{assigns: %{ueberauth_auth: auth}} = Ueberauth.call(conn, routes)
    assert auth.info.name == "Norville Rogers"
  end

  test "userinfo can be set via runtime config with default", %{
    csrf_state: csrf_state,
    csrf_conn: csrf_conn
  } do
    conn =
      conn(:get, "/auth/google/callback", %{code: "userinfo_code", state: csrf_state})
      |> set_csrf_cookies(csrf_conn)

    routes =
      Ueberauth.init()
      |> set_options(conn, userinfo_endpoint: {:system, "NOT_SET", "example.com/shaggy"})

    assert %Plug.Conn{assigns: %{ueberauth_auth: auth}} = Ueberauth.call(conn, routes)
    assert auth.info.name == "Norville Rogers"
  end

  test "userinfo uses default library value if runtime env not found", %{
    csrf_state: csrf_state,
    csrf_conn: csrf_conn
  } do
    conn =
      conn(:get, "/auth/google/callback", %{code: "userinfo_code", state: csrf_state})
      |> set_csrf_cookies(csrf_conn)

    routes = Ueberauth.init() |> set_options(conn, userinfo_endpoint: {:system, "NOT_SET"})
    assert %Plug.Conn{assigns: %{ueberauth_auth: auth}} = Ueberauth.call(conn, routes)
    assert auth.info.name == "Velma Dinkley"
  end

  test "userinfo can be set via runtime config", %{csrf_state: csrf_state, csrf_conn: csrf_conn} do
    conn =
      conn(:get, "/auth/google/callback", %{code: "userinfo_code", state: csrf_state})
      |> set_csrf_cookies(csrf_conn)

    routes = Ueberauth.init() |> set_options(conn, userinfo_endpoint: {:system, "UEBERAUTH_SCOOBY_DOO"})

    System.put_env("UEBERAUTH_SCOOBY_DOO", "example.com/scooby")
    assert %Plug.Conn{assigns: %{ueberauth_auth: auth}} = Ueberauth.call(conn, routes)
    assert auth.info.name == "Scooby Doo"
    System.delete_env("UEBERAUTH_SCOOBY_DOO")
  end

  test "client_secret can be set via {mod, fun} tuple (taking the opts)", %{
    csrf_state: csrf_state,
    csrf_conn: csrf_conn
  } do
    conn =
      conn(:get, "/auth/google/callback", %{code: "client_secret_code", state: csrf_state})
      |> set_csrf_cookies(csrf_conn)

    routes = Ueberauth.init() |> set_options(conn, custom_config: :value)

    env_config = Application.get_env(:ueberauth, Ueberauth.Strategy.Google.OAuth)

    Application.put_env(
      :ueberauth,
      Ueberauth.Strategy.Google.OAuth,
      Keyword.put(env_config, :client_secret, {__MODULE__.ClientSecret, :client_secret})
    )

    on_exit(fn ->
      Application.put_env(:ueberauth, Ueberauth.Strategy.Google.OAuth, env_config)
    end)

    assert %Plug.Conn{assigns: %{ueberauth_auth: auth}} = Ueberauth.call(conn, routes)
    assert auth.info.name == "Fred Jones"
  end

  test "state param is present in the redirect uri" do
    conn = conn(:get, "/auth/google", %{}) |> init_test_session(%{})

    routes = Ueberauth.init()
    resp = Ueberauth.call(conn, routes)

    assert [location] = get_resp_header(resp, "location")

    redirect_uri = URI.parse(location)

    assert redirect_uri.query =~ "state="
  end

  describe "error handling" do
    test "handle_callback! handles Oauth2.Error", %{csrf_state: csrf_state, csrf_conn: csrf_conn} do
      conn =
        conn(:get, "/auth/google/callback", %{code: "oauth2_error", state: csrf_state})
        |> set_csrf_cookies(csrf_conn)

      routes = Ueberauth.init([])
      assert %Plug.Conn{assigns: %{ueberauth_failure: failure}} = Ueberauth.call(conn, routes)

      assert %Ueberauth.Failure{
               errors: [%Ueberauth.Failure.Error{message: ":timeout", message_key: "error"}]
             } = failure
    end

    test "handle_callback! handles error response", %{
      csrf_state: csrf_state,
      csrf_conn: csrf_conn
    } do
      conn =
        conn(:get, "/auth/google/callback", %{code: "error_response", state: csrf_state})
        |> set_csrf_cookies(csrf_conn)

      routes = Ueberauth.init([])
      assert %Plug.Conn{assigns: %{ueberauth_failure: failure}} = Ueberauth.call(conn, routes)

      assert %Ueberauth.Failure{
               errors: [
                 %Ueberauth.Failure.Error{
                   message: "something went wrong",
                   message_key: "some error"
                 }
               ]
             } = failure
    end

    test "handle_callback! handles error response without error_description", %{
      csrf_state: csrf_state,
      csrf_conn: csrf_conn
    } do
      conn =
        conn(:get, "/auth/google/callback", %{
          code: "error_response_no_description",
          state: csrf_state
        })
        |> set_csrf_cookies(csrf_conn)

      routes = Ueberauth.init([])
      assert %Plug.Conn{assigns: %{ueberauth_failure: failure}} = Ueberauth.call(conn, routes)

      assert %Ueberauth.Failure{
               errors: [%Ueberauth.Failure.Error{message: "", message_key: "internal_failure"}]
             } = failure
    end
  end

  defmodule ClientSecret do
    def client_secret(opts) do
      assert Keyword.get(opts, :custom_config) == :value
      "custom_client_secret"
    end
  end
end
