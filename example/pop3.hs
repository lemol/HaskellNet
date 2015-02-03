{-# OPTIONS -fno-warn-missing-signatures #-}
import           Network.HaskellNet.POP3
import           Control.Monad.Trans (lift)

popServer = "pop3.mail.org"
username = ""
password = ""

main = do
    conn <- connectPop3 popServer
    print "connected"
    runPOP3 conn $ do
        userPass username password
        num <- list 4
        lift $ lift $ print $ "num " ++ show num
        msg <- retr 1
        lift $ lift $ print msg
        closePop3

