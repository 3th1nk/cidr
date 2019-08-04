# CIDR

## 基于Golang net包封装了CIDR网段和IP的常用处理方法

    import "github.com/3th1nk/cidr"

## 举个栗子

    c, _ := cidr.ParseCIDR("192.168.1.0/24")
    fmt.Println(c.Network())
    fmt.Println(c.Gateway())
    fmt.Println(c.Broadcast())

	start, end := c.IPRange()
	fmt.Println(c.IPCount(), start, end)

## 网段裂解

    # 基于子网数量划分子网段
    ns, _ := c.SubNetting(cidr.SUBNETTING_METHOD_SUBNET_NUM, 4)
    ```ns
        192.168.1.0/26
        192.168.1.64/26
        192.168.1.128/26
        192.168.1.192/26
    ```

    # 基于主机数量划分子网段
    ns, _ := c.SubNetting(cidr.SUBNETTING_METHOD_SUBNET_NUM, 64)

## 网段合并

    c2, _ := cidr.SuperNetting([]string{
        "2001:db8::/66",
        "2001:db8:0:0:8000::/66",
        "2001:db8:0:0:4000::/66",
        "2001:db8:0:0:c000::/66",
    })
    ```c2
        2001:db8::/64
    ```
