$l=New-Object Net.HttpListener; $l.Prefixes.Add('http://localhost:8765/'); $l.Start()
while($l.IsListening){ $c=$l.GetContext(); $p=$c.Request.Url.LocalPath.TrimStart('/'); if(-not $p){$p='Lead_First_Call_Dashboard.html'}
 $f=Join-Path 'C:\Call_Connect_Dashboard' $p
 if(Test-Path $f -PathType Leaf){ $b=[IO.File]::ReadAllBytes($f); $c.Response.ContentType='text/html; charset=utf-8'; $c.Response.OutputStream.Write($b,0,$b.Length) } else { $c.Response.StatusCode=404 }
 $c.Response.Close() }
