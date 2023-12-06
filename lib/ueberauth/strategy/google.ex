defmodule Ueberauth.Strategy.Google do
  @moduledoc """
  Google Strategy for Überauth.
  """

  use Ueberauth.Strategy,
    uid_field: :sub,
    default_scope: "email",
    hd: nil

  alias Ueberauth.Auth.Extra

  @session_key "ueberauth_strategy_google"

  @doc """
  Handles initial request for Google authentication.
  """
  def handle_request!(conn) do
    scopes =
      String.split(
        conn.params["scope"] || option(conn, :default_scope),
        " "
      )

    scopes =
      if "openid" in scopes do
        scopes
      else
        ["openid"] ++ scopes
      end

    authorization_params =
      []
      |> with_optional(:hd, conn)
      |> with_optional(:prompt, conn)
      |> with_optional(:access_type, conn)
      |> with_optional(:login_hint, conn)
      |> with_optional(:include_granted_scopes, conn)
      |> with_param(:access_type, conn)
      |> with_param(:prompt, conn)
      |> with_param(:login_hint, conn)
      |> with_param(:hl, conn)

    opts =
      conn
      |> options_from_conn()
      |> Map.put(:scopes, scopes)
      |> Map.put(:authorization_params, Map.new(authorization_params))

    case UeberauthOidcc.Request.handle_request(opts, conn) do
      {:ok, conn} ->
        conn

      {:error, conn, reason} ->
        UeberauthOidcc.Error.set_described_error(conn, reason, "error")
    end
  end

  @doc """
  Handles the callback from Google.
  """
  def handle_callback!(%Plug.Conn{} = conn) do
    opts = options_from_conn(conn)

    case UeberauthOidcc.Callback.handle_callback(opts, conn) do
      {:ok, conn, token, userinfo} ->
        conn
        |> put_private(:google_token, token)
        |> put_private(:google_user, userinfo)

      {:error, conn, reason} ->
        UeberauthOidcc.Error.set_described_error(conn, reason, "error")
    end
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:google_user, nil)
    |> put_private(:google_token, nil)
  end

  @doc """
  Fetches the uid field from the response.
  """
  def uid(conn) do
    uid_field =
      conn
      |> option(:uid_field)
      |> to_string

    conn.private.google_user[uid_field]
  end

  @doc """
  Includes the credentials from the google response.
  """
  def credentials(conn) do
    token = conn.private.google_token
    credentials = UeberauthOidcc.Auth.credentials(token)
    %{credentials | other: %{}}
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """
  def info(conn) do
    token = conn.private.google_token
    user = conn.private.google_user

    info = UeberauthOidcc.Auth.info(token, user)

    %{
      info
      | birthday: info.birthday || user["birthday"],
        urls: Map.put_new(info.urls, :website, user["hd"])
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from the google callback.
  """
  def extra(conn) do
    creds = credentials(conn)

    # create a struct with the same format as the old token, even if we don't depend on OAuth2
    google_token = %{
      __struct__: OAuth2.AccessToken,
      access_token: creds.token,
      refresh_token: creds.refresh_token,
      expires_at: creds.expires_at,
      token_type: "Bearer"
    }

    %Extra{
      raw_info: %{
        token: google_token,
        user: conn.private.google_user
      }
    }
  end

  defp with_param(opts, key, conn) do
    if value = conn.params[to_string(key)], do: Keyword.put(opts, key, value), else: opts
  end

  defp with_optional(opts, key, conn) do
    if option(conn, key), do: Keyword.put(opts, key, option(conn, key)), else: opts
  end

  defp options_from_conn(conn) do
    base_options = [
      issuer: UeberauthGoogle.ProviderConfiguration,
      userinfo: true,
      session_key: @session_key
    ]

    request_options = conn.private[:ueberauth_request_options].options
    oauth_options = Application.get_env(:ueberauth, Ueberauth.Strategy.Google.OAuth) || []

    [
      base_options,
      request_options,
      oauth_options
    ]
    |> UeberauthOidcc.Config.merge_and_expand_configuration()
    |> generate_client_secret()
    |> fix_token_url()
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end

  defp generate_client_secret(%{client_secret: {mod, fun}} = opts) do
    Map.put(opts, :client_secret, apply(mod, fun, [Keyword.new(opts)]))
  end

  defp generate_client_secret(opts) do
    opts
  end

  defp fix_token_url(%{token_url: token_endpoint} = opts) do
    opts
    |> Map.put(:token_endpoint, token_endpoint)
    |> Map.delete(:token_url)
  end

  defp fix_token_url(opts) do
    opts
  end
end
