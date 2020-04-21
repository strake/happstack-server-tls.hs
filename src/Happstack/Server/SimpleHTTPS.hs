module Happstack.Server.SimpleHTTPS
     ( TLSConf(..)
     , nullTLSConf
     , simpleHTTPS
     , simpleHTTPS'
     , simpleHTTPSWithSocket
     , simpleHTTPSWithSocket'
     ) where

import Control.Monad                 ((<=<))
import Data.Maybe                    (fromMaybe)
import Happstack.Server              (ToMessage(..), UnWebT, ServerPartT, simpleHTTP'', mapServerPartT, runValidator)
import Happstack.Server.Internal.Listen (listenOn)
import Happstack.Server.Internal.TLS (TLSConf(..), nullTLSConf, listenTLS', httpsOnSocket)
import Network.Socket                (Socket)
import OpenSSL                       (withOpenSSL)

-- |start the https:\/\/ server, and handle requests using the supplied
-- 'ServerPart'.
--
-- This function will not return, though it may throw an exception.
--
simpleHTTPS :: (ToMessage a) =>
               TLSConf           -- ^ tls server configuration
            -> ServerPartT IO a  -- ^ server part to run
            -> IO ()
simpleHTTPS = simpleHTTPS' id

-- | similar 'simpleHTTPS' but allows you to supply a function to convert 'm' to 'IO'.
simpleHTTPS' :: (ToMessage b, Monad m, Functor m) =>
                (UnWebT m a -> UnWebT IO b)
            -> TLSConf
            -> ServerPartT m a
            -> IO ()
simpleHTTPS' toIO tlsConf hs = do
    socket <- listenOn (tlsPort tlsConf)
    simpleHTTPSWithSocket' toIO socket tlsConf hs

simpleHTTPSWithSocket :: ToMessage a => Socket -> TLSConf -> ServerPartT IO a -> IO ()
simpleHTTPSWithSocket = simpleHTTPSWithSocket' id

simpleHTTPSWithSocket' :: (ToMessage b, Monad m) => (UnWebT m a -> UnWebT IO b) -> Socket -> TLSConf -> ServerPartT m a -> IO ()
simpleHTTPSWithSocket' toIO socket tlsConf hs = withOpenSSL $ do
    https <- (httpsOnSocket <$> tlsCert <*> tlsKey <*> tlsCA) tlsConf socket
    (listenTLS' <$> tlsTimeout <*> tlsLogAccess) tlsConf https $
        runValidator (fromMaybe pure (tlsValidator tlsConf)) <=< simpleHTTP'' (mapServerPartT toIO hs)
