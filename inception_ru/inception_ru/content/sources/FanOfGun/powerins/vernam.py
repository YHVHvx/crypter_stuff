def string(data):
    n=0
    while True:
        yield data[n]
        n+=1
        n%=len(data)
    
def genKey(data,l):
    s1, s2= None, None
    if len(data)%2==0:
        data.pop(0) #выбрасываем первый символ, нам нужна нечетная длина
        #обычно это часть сигнатуры типа, одинаковой для всех файлов,
        #так что она нам только мешает
    m=int(len(data)/2) #середина нашего списка
    t1=(data[:m]) #в первую ленту пойдет все до нее 
    t2=(data[m:]) #а во второю -- все остальное

    if len(t1)*len(t2)<l:
        raise Exception("Too small data to generate key")
    
    s1=string(t1) #создаем наши ленты
    s2=string(t2) #
    
    out=[] #пустой список
    for i in range(l): #цикл от 0 до l-1
        out+=[next(s1)^next(s2)] #формируем массив, ^ обозначает исключающее ИЛИ

    return out

def crypt(datafile, keyfile):
    data=open(datafile,"rb").read()
    key=open(keyfile,"rb").read()

    gamma=None
    try:
        gamma=genKey(key,len(data))
    except:
        print("Ключевой файл слишком короткий для шифрования исходного файла.")
        return

    out=[data[i]^gamma[i] for i in range(len(data))]
    with open(datafile,"wb") as f:
        f.write(bytes(out))
