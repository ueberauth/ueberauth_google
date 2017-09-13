defmodule Ueberauth.Strategy.Google.OAuth do
  @moduledoc """
  OAuth2 for Google.

  Add `client_id` and `client_secret` to your configuration:

  config :ueberauth, Ueberauth.Strategy.Google.OAuth,
    client_id: System.get_env("GOOGLE_APP_ID"),
    client_secret: System.get_env("GOOGLE_APP_SECRET")

  If you are using a release management package like Distillery and want to set
  the environment variables at runtime add `client_id_env` and
  `client_secret_env` to your configuration:

  config :ueberauth, Ueberauth.Strategy.Google.OAuth,
    client_id_env: "GOOGLE_APP_ID",
  """
  use OAuth2.Strategy

  @defaults [
     strategy: __MODULE__,
     site: "https://accounts.google.com",
     authorize_url: "/o/oauth2/v2/auth",
     token_url: "https://www.googleapis.com/oauth2/v4/token"
   ]

  @doc """
  Construct a client for requests to Google.

  This will be setup automatically for you in `Ueberauth.Strategy.Google`.

  These options are only useful for usage outside the normal callback phase of Ueberauth.
  """
  def client(opts \\ []) do
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.Google.OAuth)

    @defaults
    |> Keyword.merge(config)
    |> set_field_from_env(:client_id, :client_id_env, "GOOGLE_CLIENT_ID")
    |> set_field_from_env(:client_secret, :client_secret_env, "GOOGLE_CLIENT_SECRET")
    |> Keyword.merge(opts)
    |> OAuth2.Client.new
  end

  @doc """
  Provides the authorize url for the request phase of Ueberauth. No need to call this usually.
  """
  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.authorize_url!(params)
  end

  def get(token, url, headers \\ [], opts \\ []) do
    [token: token]
    |> client
    |> put_param("client_secret", client().client_secret)
    |> OAuth2.Client.get(url, headers, opts)
  end

  def get_access_token(params \\ [], opts \\ []) do
    case opts |> client |> OAuth2.Client.get_token(params) do
      {:error, %{body: %{"error" => error, "error_description" => description}}} ->
        {:error, {error, description}}
      {:ok, %{token: %{access_token: nil} = token}} ->
        %{"error" => error, "error_description" => description} = token.other_params
        {:error, {error, description}}
      {:ok, %{token: token}} ->
        {:ok, token}
    end
  end

  # Strategy Callbacks

  def authorize_url(client, params) do
    OAuth2.Strategy.AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    client
    |> put_param("client_secret", client.client_secret)
    |> put_header("Accept", "application/json")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers)
  end

  defp set_field_from_env(config, field, env_field, default_field) do
    env_name = config[env_field]

    cond do
      env_name == true && System.get_env(default_field) ->
        Keyword.merge(config, [{field, System.get_env(default_field)}])

      System.get_env(env_name) ->
        Keyword.merge(config, [{field, System.get_env(env_name)}])

      true ->
        config
    end
  end
end
