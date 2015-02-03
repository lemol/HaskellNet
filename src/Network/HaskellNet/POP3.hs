module Network.HaskellNet.POP3
    ( POP3
    , runPOP3
      -- * Establishing Connection
    , connectPop3Port
    , connectPop3
    , connectStream
      -- * Send Command
    , sendCommand
      -- * More Specific Operations
    , closePop3
    , user
    , pass
    , userPass
    , apop
    , auth
    , stat
    , dele
    , retr
    , top
    , rset
    , allList
    , list
    , allUIDLs
    , uidl
      -- * Other Useful Operations
    , doPop3Port
    , doPop3
    , doPop3Stream
    )
    where

import Network.HaskellNet.BSStream
import Network
import qualified Network.HaskellNet.Auth as A

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BS
import Crypto.Hash.MD5
import Numeric (showHex)

import Control.Applicative ((<$>))
import Control.Exception
import Control.Monad (when, unless)

import Data.List
import Data.Char (isSpace, isControl)

import System.IO

import Prelude hiding (catch)

import           Control.Monad.Error
import           Control.Monad.Reader

import Network.HaskellNet.POP3.Types
import Network.HaskellNet.POP3.Connection

type POP3 m a = ReaderT (POP3Connection m) (ErrorT String m) a

runPOP3 :: Monad m => POP3Connection m -> POP3 m a -> m (Either String a)
runPOP3 conn cmds = runErrorT $ runReaderT cmds conn

hexDigest :: [Char] -> [Char]
hexDigest = concatMap (flip showHex "") . B.unpack . hash . B.pack . map (toEnum.fromEnum)

blank :: Char -> Bool
blank a = isSpace a || isControl a

trimR :: ByteString -> ByteString
trimR s = let rs = BS.reverse s in
        BS.dropWhile blank rs

strip :: ByteString -> ByteString
strip = trimR . trimR

stripEnd :: ByteString -> ByteString
stripEnd = BS.reverse . trimR

-- | connecting to the pop3 server specified by the hostname and port
-- number
connectPop3Port :: String -> PortNumber -> IO (POP3Connection IO)
connectPop3Port hostname port =
    handleToStream <$> (connectTo hostname (PortNumber port))
    >>= connectStream

-- | connecting to the pop3 server specified by the hostname. 110 is
-- used for the port number.
connectPop3 :: String -> IO (POP3Connection IO)
connectPop3 = flip connectPop3Port 110

-- | connecting to the pop3 server via a stream
connectStream :: (Monad m, Functor m) => BSStream m -> m (POP3Connection m)
connectStream st =
    do (resp, msg) <- response st
       when (resp == Err) $ fail "cannot connect"
       let code = last $ BS.words msg
       if BS.head code == '<' && BS.last code == '>'
         then return $ newConnection st (BS.unpack code)
         else return $ newConnection st ""

response :: (Monad m, Functor m) => BSStream m -> m (Response, ByteString)
response st =
    do reply <- strip <$> bsGetLine st
       if (BS.pack "+OK") `BS.isPrefixOf` reply
         then return (Ok, BS.drop 4 reply)
         else return (Err, BS.drop 5 reply)

-- | parse mutiline of response
responseML :: (Monad m, Functor m) => POP3 m (Response, ByteString)
responseML = do
    st <- asks stream
    lift $ lift $ do
       reply <- strip <$> bsGetLine st
       if (BS.pack "+OK") `BS.isPrefixOf` reply
         then do rest <- getRest st
                 return (Ok, BS.unlines (BS.drop 4 reply : rest))
         else return (Err, BS.drop 5 reply)
    where getRest st = do l <- stripEnd <$> bsGetLine st
                          if l == BS.singleton '.'
                              then return []
                              else (l:) <$> getRest st

-- | sendCommand sends a pop3 command via a pop3 connection.  This
-- action is too generic. Use more specific actions
sendCommand :: (Monad m, Functor m) => Command -> POP3 m (Response, ByteString)
sendCommand (LIST Nothing) = do
    strm <- asks stream
    lift $ lift $ bsPutCrLf strm (BS.pack "LIST")
    responseML
sendCommand (UIDL Nothing) = do
    strm <- asks stream
    lift $ lift $ bsPutCrLf strm (BS.pack "UIDL")
    responseML
sendCommand (RETR msg) = do
    strm <- asks stream
    lift $ lift $ bsPutCrLf strm (BS.pack $ "RETR " ++ show msg)
    responseML
sendCommand (TOP msg n) = do
    strm <- asks stream
    lift $ lift $ bsPutCrLf strm (BS.pack $ "TOP " ++ show msg ++ " " ++ show n)
    responseML
sendCommand (AUTH A.LOGIN username password) = do
    strm <- asks stream
    lift $ lift $ do
        bsPutCrLf strm $ BS.pack "AUTH LOGIN"
        bsGetLine strm
        bsPutCrLf strm $ BS.pack userB64
        bsGetLine strm
        bsPutCrLf strm $ BS.pack passB64
        response strm
    where (userB64, passB64) = A.login username password
sendCommand (AUTH at username password) = do
    strm <- asks stream
    lift $ lift $ do
        bsPutCrLf strm $ BS.pack $ unwords ["AUTH", show at]
        c <- bsGetLine strm
        let challenge =
                if BS.take 2 c == BS.pack "+ "
                then A.b64Decode $ BS.unpack $ head $
                    dropWhile (isSpace . BS.last) $ BS.inits $ BS.drop 2 c
                else ""
        bsPutCrLf strm $ BS.pack $ A.auth at challenge username password
        response strm
sendCommand command = do
    conn <- ask
    strm <- asks stream
    lift $ lift $ bsPutCrLf strm (BS.pack $ commandStr conn) >> response strm
    where commandStr conn = case command of
                         (USER name)  -> "USER " ++ name
                         (PASS passw) -> "PASS " ++ passw
                         NOOP         -> "NOOP"
                         QUIT         -> "QUIT"
                         STAT         -> "STAT"
                         (DELE msg)   -> "DELE " ++ show msg
                         RSET         -> "RSET"
                         (LIST msg)   -> "LIST " ++ maybe "" show msg
                         (UIDL msg)   -> "UIDL " ++ maybe "" show msg
                         (APOP usern passw) -> "APOP " ++ usern ++ " " ++
                                             hexDigest (apopKey conn ++ passw)
                         (AUTH _ _ _) -> error "BUG: AUTH should not get matched here"
                         (RETR _) -> error "BUG: RETR should not get matched here"
                         (TOP _ _) -> error "BUG: TOP should not get matched here"

user :: (Monad m, Functor m) => String -> POP3 m ()
user name = do (resp, _) <- sendCommand (USER name)
               when (resp == Err) $ fail "cannot send user name"

pass :: (Monad m, Functor m) => String -> POP3 m ()
pass pwd = do (resp, _) <- sendCommand (PASS pwd)
              when (resp == Err) $ fail "cannot send password"

userPass :: (Monad m, Functor m) => A.UserName -> A.Password -> POP3 m ()
userPass name pwd = user name >> pass pwd

auth :: (Monad m, Functor m) => A.AuthType -> A.UserName -> A.Password
     -> POP3 m ()
auth at username password =
    do (resp, msg) <- sendCommand (AUTH at username password)
       unless (resp == Ok) $ fail $ "authentication failed: " ++ BS.unpack msg

apop :: (Monad m, Functor m) => String -> String -> POP3 m ()
apop name pwd =
    do (resp, msg) <- sendCommand (APOP name pwd)
       when (resp == Err) $ fail $ "authentication failed: " ++ BS.unpack msg

stat :: (Monad m, Functor m) => POP3 m (Int, Int)
stat = do (resp, msg) <- sendCommand STAT
          when (resp == Err) $ fail "cannot get stat info"
          let (nn, mm) = BS.span (/=' ') msg
          return (read $ BS.unpack nn, read $ BS.unpack $ BS.tail mm)

dele :: (Monad m, Functor m) => Int -> POP3 m ()
dele n = do (resp, _) <- sendCommand (DELE n)
            when (resp == Err) $ fail "cannot delete"

retr :: (Monad m, Functor m) => Int -> POP3 m ByteString
retr n = do (resp, msg) <- sendCommand (RETR n)
            when (resp == Err) $ fail "cannot retrieve"
            return $ BS.tail $ BS.dropWhile (/='\n') msg

top :: (Monad m, Functor m) => Int -> Int -> POP3 m ByteString
top n m = do (resp, msg) <- sendCommand (TOP n m)
             when (resp == Err) $ fail "cannot retrieve"
             return $ BS.tail $ BS.dropWhile (/='\n') msg

rset :: (Monad m, Functor m) => POP3 m ()
rset = do (resp, _) <- sendCommand RSET
          when (resp == Err) $ fail "cannot reset"

allList :: (Monad m, Functor m) => POP3 m [(Int, Int)]
allList = do (resp, lst) <- sendCommand (LIST Nothing)
             when (resp == Err) $ fail "cannot retrieve the list"
             return $ map f $ tail $ BS.lines lst
    where f s = let (n1, n2) = BS.span (/=' ') s
                in (read $ BS.unpack n1, read $ BS.unpack $ BS.tail n2)

list :: (Monad m, Functor m) => Int -> POP3 m Int
list n = do (resp, lst) <- sendCommand (LIST (Just n))
            when (resp == Err) $ fail "cannot retrieve the list"
            let (_, n2) = BS.span (/=' ') lst
            return $ read $ BS.unpack $ BS.tail n2

allUIDLs :: (Monad m, Functor m) => POP3 m [(Int, ByteString)]
allUIDLs = do (resp, lst) <- sendCommand (UIDL Nothing)
              when (resp == Err) $ fail "cannot retrieve the uidl list"
              lift $ lift $ return $ map f $ tail $ BS.lines lst
    where f s = let (n1, n2) = BS.span (/=' ') s in (read $ BS.unpack n1, n2)

uidl :: (Monad m, Functor m) => Int -> POP3 m ByteString
uidl n = do (resp, msg) <- sendCommand (UIDL (Just n))
            when (resp == Err) $ fail "cannot retrieve the uidl data"
            lift $ lift $ return $ BS.tail $ BS.dropWhile (/=' ') msg

closePop3 :: (Monad m, Functor m) => POP3 m ()
closePop3 = do sendCommand QUIT
               asks stream >>= lift.lift.bsClose

doPop3Port :: String -> PortNumber -> (POP3Connection IO -> IO a) -> IO a
doPop3Port host port execution =
    bracket (connectPop3Port host port) (flip runPOP3 closePop3) execution

doPop3 :: String -> (POP3Connection IO -> IO a) -> IO a
doPop3 host execution = doPop3Port host 110 execution

doPop3Stream :: BSStream IO -> (POP3Connection IO -> IO b) -> IO b
doPop3Stream conn execution = bracket (connectStream conn) (flip runPOP3 closePop3) execution

crlf :: BS.ByteString
crlf = BS.pack "\r\n"

bsPutCrLf :: Monad m => BSStream m -> ByteString -> m ()
bsPutCrLf h s = bsPut h s >> bsPut h crlf >> bsFlush h
