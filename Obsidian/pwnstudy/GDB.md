# 调试命令

| 调试命令(缩写) | 作用 |
|-------|---------|
| break(b) | 在源代码指定的某一行设置断点|


## 断点
### 设置断点
使用`break`命令,可以用`b`代替,常用语法格式为:`break ...`

|填充内容|含义|
|-|-|
|\*0xFFFFF|在地址0xFFFFF处设置断点|
|+5/-5|在当前行数向后/前5行处设置断点|
|function|在函数function处设置断点|
|filename:function|在文件filename中的function处设置断点|
|5|在代码第5行处设置断点|
|filename:5|在文件filename中代码第5行处设置断点|

`tbreak`命令,设置语法和break类似,不同之处在于`tbreak`只会打断一次,在程序暂停后会自动删除.

### 查看断点
`info break`或`info breakpoints`

### 删除/禁用断点
使用`clear`命令,语法格式为`clear ...`,用于删除指定代码行号/地址/函数处的断点.
使用`delete`命令,可以用`d`代替,语法格式为`delete ...`,用于删除编号为...的断点,如不指定编号,则删除全部断点.

## 单步调试
### next(n)
当遇到包含调用函数的语句时，无论函数内部包含多少行代码，`next`指令都会一步执行完。也就是说，对于调用的函数来说，`netx`命令只会将其视作一行代码。
### step(s)
当`step`命令所执行的代码行中包含函数时，会进入该函数内部，并在函数第一行代码处停止执行。
### until(u)
当`until`后不接参数时,会运行当前循环体直至跳出循环.

## 栈
### 查看栈
`stack ...`,输出当前栈中前...层的内容

## 寄存器
### 查看寄存器
`info register`,输出当前寄存器中的内容