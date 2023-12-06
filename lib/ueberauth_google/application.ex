defmodule UeberauthGoogle.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      {Oidcc.ProviderConfiguration.Worker,
       %{
         name: UeberauthGoogle.ProviderConfiguration,
         issuer: "https://accounts.google.com"
       }}
    ]

    opts = [strategy: :one_for_one, name: UeberauthGoogle.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
